from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import date, datetime, time as wall_time, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler
from uuid import UUID, uuid4
from zipfile import BadZipFile

ARM = "https://management.azure.com"
ARG_URL = ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
MG_PREFIX = "/providers/microsoft.management/managementgroups/"
KST = timezone(timedelta(hours=9), "KST")
READ_ROLES = {
    "acdd72a7-3385-48ef-bd42-f606fba81ae7",  # Reader
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
}
RESULT_LABELS = {
    "EXPECTED_DELETED": "정상 삭제",
    "EXPECTED_REMAINING": "미삭제",
    "NOT_IN_BASELINE": "검증 불가 (A자료에 없음)",
    "UNEXPECTED_DELETED": "오삭제",
}
ROLE_QUERY = (
    "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' "
    "| project id, name, type, tenantId, subscriptionId, properties | order by id asc"
)
SCOPE_QUERY = (
    "ResourceContainers | where type in~ "
    "('microsoft.resources/subscriptions', 'microsoft.management/managementgroups') "
    "| project id, name, type, tenantId, subscriptionId | order by id asc"
)
ROLE_ID = re.compile(
    r"^(?:/subscriptions/[0-9a-f-]{36}(?:/[^?#]*)?"
    r"|/providers/microsoft\.management/managementgroups/[^/?#]+|)"
    r"/providers/microsoft\.authorization/roleassignments/"
    r"([0-9a-f-]{36})$", re.I,
)


class VerificationError(Exception):
    pass


class HttpFailure(VerificationError):
    def __init__(self, status: int, retry_after: float = 0):
        super().__init__(f"HTTP {status}; no successful snapshot or delivery was recorded.")
        self.status = status
        self.retry_after = retry_after


class NotConverged(VerificationError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(value: datetime | None = None) -> str:
    return (value or now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def guid(value: Any) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value)),
        "Expected a hyphenated GUID.")
    return str(UUID(value))


def assignment_key(value: Any) -> str:
    require(isinstance(value, str), "roleAssignment must be a GUID or full ARM ID.")
    value = value.strip().rstrip("/").lower()
    if value.startswith("/"):
        match = ROLE_ID.fullmatch(value)
        require(match is not None, "Invalid role assignment ARM ID.")
        assert match is not None
        guid(match.group(1))
        require("/../" not in value and "/./" not in value and "%" not in value,
                "Unsafe role assignment ARM ID.")
        if value.startswith("/subscriptions/"):
            guid(value.split("/")[2])
        return value
    return guid(value)


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("wb") as stream:
        for row in rows:
            stream.write(canonical(row) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def write_verification_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Role Assignment ID", "삭제", "오삭제", "미삭제", "판정",
                         "Role Assignment Resource ID", "Excel Rows"])
        for row in rows:
            flags = ["검증 불가" if row[field] is None else "예" if row[field] else "아니오"
                     for field in ("deleted", "unexpectedDeleted", "notDeleted")]
            writer.writerow([row["roleAssignmentId"], *flags, row["result"], row["assignmentId"],
                             ",".join(map(str, row["excelRows"]))])
        stream.flush()
        os.fsync(stream.fileno())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    require(all(isinstance(row, dict) for row in rows), "Invalid JSONL object.")
    return rows


def load_config(path: Path, local_only: bool = False) -> dict[str, Any]:
    config = read_json(path)
    require(isinstance(config, dict), "Config must be a JSON object.")
    require("expected_subscription_ids" not in config,
            "Remove obsolete expected_subscription_ids; subscriptions are discovered from the management group.")
    allowed = {"tenant_id", "excel_path", "sheet_name",
               "active_only", "output_directory", "workspace_id", "workspace_key_env",
               "log_type", "stability_seconds", "capture_attempts"}
    require(not set(config) - allowed, "Unknown config fields; check config.example.json.")
    config["tenant_id"] = guid(config.get("tenant_id"))
    config["workspace_id"] = (None if local_only and not config.get("workspace_id")
                              else guid(config.get("workspace_id")))
    for field in ("excel_path", "output_directory"):
        require(isinstance(config.get(field), str) and bool(config[field].strip()),
                f"Missing {field}.")
        config[field] = str((path.parent / config[field]).resolve())
    require(isinstance(config.get("sheet_name"), str) and bool(config["sheet_name"]),
            "Specify the Excel sheet_name explicitly.")
    config.setdefault("active_only", True)
    require(isinstance(config["active_only"], bool), "active_only must be boolean.")
    config.setdefault("workspace_key_env", "LA_WORKSPACE_KEY")
    require(isinstance(config["workspace_key_env"], str) and bool(re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*", config["workspace_key_env"])), "Invalid key environment name.")
    config.setdefault("log_type", "KTRoleDeletionVerification")
    require(isinstance(config["log_type"], str) and bool(re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_]{0,99}", config["log_type"]))
        and not config["log_type"].endswith("_CL"), "log_type must omit the _CL suffix.")
    for field, default, minimum, maximum in (
        ("stability_seconds", 30, 1, 600), ("capture_attempts", 5, 2, 30)
    ):
        config.setdefault(field, default)
        require(type(config[field]) is int and minimum <= config[field] <= maximum,
                f"Invalid {field}.")
    return config


def lab_scope(value: str) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(
        r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/rg-ra-verifier-[a-zA-Z0-9_-]+",
        value, re.I)), "Lab scope must be the full ARM ID of an rg-ra-verifier-* resource group.")
    guid(value.split("/")[2])
    return value.lower()


def management_group_id(value: str) -> str:
    require(isinstance(value, str), "Management group ID must be a string.")
    value = value.strip().rstrip("/").lower()
    if value.startswith(MG_PREFIX):
        value = value[len(MG_PREFIX):]
    require(bool(re.fullmatch(r"[a-z0-9][a-z0-9._()-]{0,89}", value)) and not value.endswith("."),
            "Use a management group ID (not display name) or its full ARM ID.")
    return value


def load_targets(path: Path, sheet_name: str, active_only: bool) -> list[dict[str, Any]]:
    from openpyxl import load_workbook
    from openpyxl.utils.exceptions import InvalidFileException

    try:
        book = load_workbook(path, read_only=True, data_only=False)
    except (BadZipFile, InvalidFileException):
        raise VerificationError("X must be a readable XLSX/XLSM workbook.") from None
    try:
        require(sheet_name in book.sheetnames, "Configured worksheet does not exist.")
        rows = book[sheet_name].iter_rows()
        header_cells = next(rows, ())
        headers = [str(cell.value).strip() if cell.value is not None else ""
                   for cell in header_cells]
        for name in ("roleAssignment", "Active"):
            require(headers.count(name) == 1, f"Expected exactly one {name} column.")
        assignment_index, active_index = headers.index("roleAssignment"), headers.index("Active")
        targets: dict[str, dict[str, Any]] = {}
        aliases: dict[str, str] = {}
        for number, cells in enumerate(rows, 2):
            if all(cell.value is None for cell in cells):
                continue
            require(cells[assignment_index].data_type != "f"
                    and cells[active_index].data_type != "f",
                    f"Excel row {number}: formulas are not allowed in matching columns.")
            raw_active = cells[active_index].value
            require(isinstance(raw_active, bool) or (
                isinstance(raw_active, str) and raw_active.strip().upper() in ("TRUE", "FALSE")),
                f"Excel row {number}: Active must be TRUE or FALSE.")
            active = raw_active if isinstance(raw_active, bool) else raw_active.strip().upper() == "TRUE"
            try:
                key = assignment_key(cells[assignment_index].value)
            except VerificationError as exc:
                raise VerificationError(f"Excel row {number}: {exc}") from None
            name = key.rsplit("/", 1)[-1]
            require(name not in aliases or aliases[name] == key,
                    f"Excel row {number}: do not mix GUID/full-ID aliases for the same target.")
            aliases[name] = key
            selected = active or not active_only
            if key in targets:
                require(targets[key]["selected"] == selected,
                        f"Excel row {number}: conflicting Active flags.")
                targets[key]["excelRows"].append(number)
            else:
                targets[key] = {"key": key, "selected": selected, "excelRows": [number]}
        require(any(row["selected"] for row in targets.values()), "No selected deletion targets.")
        return sorted(targets.values(), key=lambda row: row["key"])
    finally:
        book.close()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


class Wire:
    def __init__(self) -> None:
        tls = ssl.create_default_context()
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=tls))

    def send(self, method: str, url: str, headers: dict[str, str],
             body: bytes | None = None) -> tuple[int, bytes]:
        try:
            with self.opener.open(Request(url, data=body, headers=headers, method=method),
                                  timeout=60) as response:
                payload = response.read(64 * 1024 * 1024 + 1)
                require(len(payload) <= 64 * 1024 * 1024, "HTTP response too large.")
                return response.status, payload
        except HTTPError as exc:
            retry = exc.headers.get("Retry-After", "0")
            try:
                delay = float(retry)
            except ValueError:
                try:
                    delay = (parsedate_to_datetime(retry) - now()).total_seconds()
                except (ValueError, TypeError, OverflowError):
                    delay = 0
            raise HttpFailure(exc.code, min(300, max(0, delay))) from None
        except (URLError, TimeoutError, OSError):
            raise HttpFailure(0) from None


class CliAuth:
    def __init__(self, tenant_id: str):
        self.executable = shutil.which("az")
        require(self.executable is not None, "Install Azure CLI and run az login --tenant <tenant>.")
        account = self.command(["account", "show"])
        require(account.get("environmentName") == "AzureCloud",
                "This tool supports Azure public cloud only.")
        require(account.get("user", {}).get("type", "").lower() == "user",
                "Use an interactive Entra user, not a service principal or managed identity.")
        require(guid(account.get("tenantId")) == tenant_id, "Azure CLI tenant mismatch.")
        self.tenant_id = tenant_id
        self.access_token = ""
        self.expires = 0.0
        self.principal_id = ""
        self.token()

    def command(self, arguments: list[str]) -> dict[str, Any]:
        assert self.executable is not None
        try:
            result = subprocess.run([self.executable, *arguments, "--output", "json",
                                     "--only-show-errors"], capture_output=True, check=False,
                                    text=True, encoding="utf-8", timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            raise VerificationError("Azure CLI could not run; check installation/login.") from None
        require(result.returncode == 0, "Azure CLI failed; run az login and check tenant/access.")
        data = json.loads(result.stdout)
        require(isinstance(data, dict), "Azure CLI returned a non-object.")
        return data

    def token(self, refresh: bool = False) -> str:
        if refresh or time.time() >= self.expires - 120:
            token = self.command(["account", "get-access-token", "--tenant", self.tenant_id,
                                  "--resource", ARM + "/"])
            access_token = token.get("accessToken")
            require(isinstance(access_token, str), "Azure CLI returned no access token.")
            try:
                encoded = access_token.split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
                principal_id = guid(claims.get("oid"))
                require(guid(claims.get("tid")) == self.tenant_id, "Token tenant mismatch.")
                require(claims.get("idtyp") != "app", "Application tokens are not supported.")
                expires = float(claims["exp"])
            except (IndexError, ValueError, KeyError, binascii.Error):
                raise VerificationError("Azure CLI returned an invalid ARM JWT.") from None
            require(not self.principal_id or principal_id == self.principal_id,
                    "Azure CLI user changed during capture.")
            self.principal_id, self.access_token, self.expires = principal_id, access_token, expires
        return self.access_token


class Azure:
    def __init__(self, config: dict[str, Any], auth: CliAuth, wire: Wire):
        self.config, self.auth, self.wire = config, auth, wire
        self.management_scope_ids: set[str] = set()

    def request(self, method: str, url: str, body: Any = None,
                allow_missing: bool = False) -> dict[str, Any] | None:
        parsed = urlsplit(url)
        require(parsed.scheme == "https" and parsed.netloc == "management.azure.com"
                and not parsed.fragment, "Untrusted ARM URL.")
        require(method == "GET" or (method == "POST" and url == ARG_URL),
                "Only ARM GET and read-only ARG POST are permitted.")
        scope = self.config.get("_lab_resource_group_id")
        if scope and method == "GET":
            path = parsed.path.lower().rstrip("/")
            require(path == scope or path.startswith(scope + "/"), "ARM GET escaped the lab RG.")
        for attempt in range(5):
            try:
                status, payload = self.wire.send(method, url, {
                    "Authorization": "Bearer " + self.auth.token(),
                    "Content-Type": "application/json",
                }, None if body is None else canonical(body))
                require(status == 200, "Unexpected ARM response status.")
                result = json.loads(payload)
                require(isinstance(result, dict) and "error" not in result, "Invalid ARM response.")
                return result
            except HttpFailure as exc:
                if allow_missing and exc.status == 404:
                    return None
                if exc.status == 401 and attempt == 0:
                    self.auth.token(refresh=True)
                    continue
                if attempt == 4 or (exc.status not in (0, 429) and exc.status < 500):
                    raise
                time.sleep(max(exc.retry_after, min(30, 2 ** attempt)))
        raise VerificationError("ARM retry budget exhausted.")

    def graph(self, query: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        tokens: set[str] = set()
        token = None
        total = None
        scope = self.config.get("_lab_resource_group_id")
        selected_group = self.config.get("_management_group_id")
        require(bool(scope or selected_group), "Select --management-group or --lab-resource-group.")
        if scope:
            query += f" | where id startswith '{scope}/'"
        for _ in range(100000):
            options: dict[str, Any] = {
                "$top": 1000, "resultFormat": "objectArray", "allowPartialScopes": False,
                "authorizationScopeFilter": "AtScopeAndBelow",
            }
            if token:
                options["$skipToken"] = token
            selection = ({"subscriptions": [scope.split("/")[2]]} if scope
                         else {"managementGroups": [selected_group]})
            result = self.request("POST", ARG_URL, {
                **selection, "query": query, "options": options,
            })
            assert result is not None
            page = result.get("data")
            require(isinstance(page, list), "ARG data is not an objectArray.")
            require(type(result.get("count")) is int and result["count"] == len(page),
                    "ARG count mismatch.")
            page_total = result.get("totalRecords")
            require(type(page_total) is int and page_total >= 0, "ARG totalRecords missing.")
            if total is None:
                total = page_total
            require(total == page_total, "ARG changed while paging; retry the capture.")
            for row in page:
                require(isinstance(row, dict) and isinstance(row.get("id"), str),
                        "ARG returned a row without an ID.")
                key = row["id"].lower().rstrip("/")
                require(not scope or key.startswith(scope + "/"),
                        "ARG returned a record outside the lab RG.")
                if selected_group and query == ROLE_QUERY:
                    require(bool(self.management_scope_ids),
                            "Management group hierarchy must be checked before assignment capture.")
                    assignment_scope = row.get("properties", {}).get("scope", "").lower().rstrip("/")
                    container = ("/".join(assignment_scope.split("/")[:3])
                                 if assignment_scope.startswith("/subscriptions/") else assignment_scope)
                    require(container in self.management_scope_ids,
                            "ARG returned an assignment outside the selected management group hierarchy.")
                require(key not in seen_ids, "ARG duplicate ID while paging; retry the capture.")
                seen_ids.add(key)
                rows.append(row)
            token = result.get("$skipToken")
            truncated = result.get("resultTruncated")
            require(truncated in (True, False, "true", "false"), "ARG resultTruncated missing.")
            if not token:
                require(truncated in (False, "false") and len(rows) == total,
                        "ARG result is incomplete; snapshot rejected.")
                return sorted(rows, key=lambda row: row["id"].lower())
            require(isinstance(token, str) and token not in tokens and bool(page),
                    "ARG paging token loop or empty continuation page.")
            tokens.add(token)
        raise VerificationError("ARG page budget exceeded.")

    def management_inventory(self) -> tuple[list[dict[str, Any]], set[str]]:
        root = MG_PREFIX + self.config["_management_group_id"]
        group = self.request("GET", ARM + root + "?api-version=2020-05-01&$expand=path")
        assert group is not None
        require(group.get("id", "").lower() == root, "Management group response ID mismatch.")
        details = group.get("properties", {}).get("details", {})
        ancestors = details.get("path", [])
        require(isinstance(ancestors, list), "Invalid management group ancestor path.")
        read_scopes = {root, "/"} | {MG_PREFIX + management_group_id(item["name"]) for item in ancestors}
        parent = details.get("parent") or {}
        scopes = [{"id": root, "name": self.config["_management_group_id"],
                   "type": "microsoft.management/managementgroups", "subscriptionId": "",
                   "tenantId": self.config["tenant_id"], "parentId": parent.get("id", "").lower()}]
        seen_ids = {root}
        url = ARM + root + "/descendants?api-version=2020-05-01"
        seen_urls: set[str] = set()
        while url:
            require(urlsplit(url).path.lower() == root + "/descendants" and url not in seen_urls,
                    "Invalid management group descendants continuation.")
            seen_urls.add(url)
            result = self.request("GET", url)
            assert result is not None
            require(isinstance(result.get("value"), list), "Invalid management group descendants response.")
            for item in result["value"]:
                identifier = item.get("id", "").lower()
                if identifier.startswith(MG_PREFIX):
                    name = management_group_id(identifier)
                    identifier = MG_PREFIX + name
                    kind, subscription = "microsoft.management/managementgroups", ""
                else:
                    require(bool(re.fullmatch(r"/subscriptions/[0-9a-f-]{36}", identifier)),
                            "Invalid descendant resource ID.")
                    subscription = guid(identifier.split("/")[2])
                    name, kind = subscription, "microsoft.resources/subscriptions"
                parent_id = item.get("properties", {}).get("parent", {}).get("id", "").lower()
                require(parent_id.startswith(MG_PREFIX), "Descendant parent group is missing.")
                require(identifier not in seen_ids, "Duplicate management group descendant.")
                seen_ids.add(identifier)
                scopes.append({"id": identifier, "name": name, "type": kind,
                               "subscriptionId": subscription, "tenantId": self.config["tenant_id"],
                               "parentId": parent_id})
            url = result.get("nextLink") or ""
        parents = {item["id"]: item["parentId"] for item in scopes}
        for item in scopes[1:]:
            parent_id, visited = item["parentId"], {item["id"]}
            while parent_id != root:
                require(parent_id in parents and parent_id not in visited,
                        "Incomplete or cyclic management group hierarchy.")
                visited.add(parent_id)
                parent_id = parents[parent_id]
        require(sum(bool(item["subscriptionId"]) for item in scopes) < 10000,
                "Management group contains 10000 or more subscriptions; use a smaller management group.")
        return sorted(scopes, key=lambda item: item["id"]), read_scopes

    def check_scopes(self) -> list[dict[str, Any]]:
        scope = self.config.get("_lab_resource_group_id")
        selected_group = self.config.get("_management_group_id")
        require(bool(scope or selected_group), "Select --management-group or --lab-resource-group.")
        root = scope or MG_PREFIX + selected_group
        inventory, read_scopes = (self.management_inventory() if selected_group else (None, {root}))
        group = None
        if scope:
            group = self.request("GET", ARM + scope + "?api-version=2022-09-01")
            assert group is not None
            require(group.get("id", "").lower() == scope
                    and group.get("tags", {}).get("purpose") == "role-assignment-verifier-live-test",
                    "Lab RG ID/tag mismatch; existing non-test RGs cannot be used.")
        url = ARM + root + (
            "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            "&$filter=atScope()")
        root_assignments: list[dict[str, Any]] = []
        seen: set[str] = set()
        while url:
            require(url not in seen, "Root assignment pagination loop.")
            seen.add(url)
            result = self.request("GET", url)
            assert result is not None
            require(isinstance(result.get("value"), list), "Invalid root assignment response.")
            root_assignments.extend(result["value"])
            url = result.get("nextLink") or ""
        require(any(
            (row.get("properties", {}).get("scope", "").lower().rstrip("/") or "/") in read_scopes
            and row["properties"].get("principalId", "").lower() == self.auth.principal_id
            and row["properties"].get("roleDefinitionId", "").lower().rsplit("/", 1)[-1] in READ_ROLES
            and not row["properties"].get("condition")
            for row in root_assignments
        ), "Coverage guard requires an unconditional direct Reader/Contributor/Owner assignment "
           "to this user at the selected management group/ancestor or lab RG. "
           "Group-only/custom-role coverage is not auto-verified.")
        if group is not None:
            return [{"id": scope, "name": group["name"],
                     "type": "microsoft.resources/subscriptions/resourcegroups",
                     "subscriptionId": scope.split("/")[2], "tenantId": self.config["tenant_id"]}]
        assert inventory is not None
        scopes = self.graph(SCOPE_QUERY)
        identifiers = {item["id"] for item in inventory}
        visible = {item["id"].lower() for item in scopes}
        require(identifiers <= visible, "ARG is missing part of the selected management group hierarchy.")
        require(not (visible - identifiers - read_scopes),
                "ARG hierarchy differs from the ARM-discovered management group hierarchy.")
        self.management_scope_ids = identifiers
        return inventory

    def capture(self, prechecked_scopes: list[dict[str, Any]] | None = None
                ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str, str]:
        started = stamp()
        scopes = self.check_scopes()
        if prechecked_scopes is not None:
            require(prechecked_scopes == scopes, "Scopes changed since baseline preflight.")
        roles = self.graph(ROLE_QUERY)
        require(bool(roles) or bool(self.config.get("_management_group_id")),
                "Empty organization role assignment snapshot rejected.")
        role_index(roles)
        current_scopes = self.check_scopes()
        require(current_scopes == scopes, "Scopes changed during capture.")
        return roles, scopes, started, stamp()

    def confirm(self, before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]],
                targets: list[dict[str, Any]]) -> None:
        ids = set(before) - set(after)
        for target, match in resolved_targets(targets, before):
            if target["selected"]:
                if match:
                    ids.add(match)
        for target, match in resolved_targets(targets, after):
            if target["selected"] and match:
                ids.add(match)
        for key in sorted(ids):
            actual = self.request("GET", ARM + key + "?api-version=2022-04-01", allow_missing=True)
            if key not in after:
                if actual is not None:
                    raise NotConverged("ARG missing assignment still exists in ARM; retrying.")
            elif actual is None or role_identity(actual) != role_identity(after[key]):
                raise NotConverged("ARG and ARM target state differ; retrying.")


def role_identity(row: dict[str, Any]) -> bytes:
    properties = row.get("properties", {})
    definition = properties.get("roleDefinitionId")
    require(isinstance(definition, str), "Missing roleDefinitionId for identity comparison.")
    return canonical({
        **{field: str(properties.get(field) or "").lower()
           for field in ("scope", "principalId")},
        "roleDefinitionId": guid(definition.rstrip("/").rsplit("/", 1)[-1]),
        **{field: properties.get(field) for field in ("condition", "conditionVersion")},
    })


def role_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for row in rows:
        key = assignment_key(row.get("id"))
        name = guid(row.get("name"))
        require(key.startswith("/") and key.rsplit("/", 1)[-1] == name,
                "Assignment name/ARM ID mismatch.")
        require(key not in result and name not in names, "Duplicate assignment ID or GUID.")
        properties = row.get("properties")
        require(isinstance(properties, dict) and all(isinstance(properties.get(field), str)
                and properties[field] for field in ("scope", "principalId", "roleDefinitionId")),
                "Missing assignment identity properties.")
        require(key.rsplit("/providers/microsoft.authorization/roleassignments/", 1)[0]
                == properties["scope"].lower().rstrip("/"),
                "Assignment scope/ARM ID mismatch.")
        result[key] = row
        names.add(name)
    return result


def resolved_targets(targets: list[dict[str, Any]], index: dict[str, dict[str, Any]]
                     ) -> Iterator[tuple[dict[str, Any], str | None]]:
    names = {key.rsplit("/", 1)[-1]: key for key in index}
    for target in targets:
        key = target["key"]
        yield target, (key if key in index else None) if key.startswith("/") else names.get(key)


def compare(before_rows: list[dict[str, Any]], after_rows: list[dict[str, Any]],
            targets: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    before, after = role_index(before_rows), role_index(after_rows)
    removed = set(before) - set(after)
    expected: set[str] = set()
    results: list[dict[str, Any]] = []
    current = {row["key"]: key for row, key in resolved_targets(targets, after)}
    for target, key in resolved_targets(targets, before):
        if not target["selected"]:
            continue
        if key:
            expected.add(key)
        status = "NOT_IN_BASELINE" if key is None else (
            "EXPECTED_DELETED" if key in removed and current[target["key"]] is None
            else "EXPECTED_REMAINING")
        results.append({"status": status, "targetKey": target["key"],
                        "roleAssignmentId": guid((key or target["key"]).rsplit("/", 1)[-1]),
                        "assignmentId": key or "",
                        "currentAssignmentId": current[target["key"]] or "",
                        "excelRows": target["excelRows"]})
    for key in sorted(removed - expected):
        results.append({"status": "UNEXPECTED_DELETED", "targetKey": key,
                        "roleAssignmentId": guid(key.rsplit("/", 1)[-1]),
                        "assignmentId": key, "currentAssignmentId": "", "excelRows": []})
    for row in results:
        status = row["status"]
        row.update(
            deleted=None if status == "NOT_IN_BASELINE" else status == "EXPECTED_DELETED",
            unexpectedDeleted=None if status == "NOT_IN_BASELINE" else status == "UNEXPECTED_DELETED",
            notDeleted=None if status == "NOT_IN_BASELINE" else status == "EXPECTED_REMAINING",
            result=RESULT_LABELS[status],
        )
    return [before[key] for key in sorted(removed)], results


def event(run_id: str, phase: str, record_type: str, **fields: Any) -> dict[str, Any]:
    value = {"RunId": run_id, "Phase": phase, "RecordType": record_type, **fields}
    value["EventId"] = "event-" + hashlib.sha256(canonical(value)).hexdigest()
    return value


def timestamped_name(name: str, file_timestamp: str) -> str:
    require(bool(re.fullmatch(r"\d{8}_\d{6}_KST", file_timestamp)), "Invalid file timestamp.")
    source = Path(name)
    require(source.name == name and name not in ("", ".", ".."), "Invalid evidence file name.")
    return f"{source.stem}_{file_timestamp}{source.suffix}"


def metadata_path(path: Path) -> Path:
    candidates = list(path.glob("metadata_*.json"))
    if (path / "metadata.json").is_file():
        candidates.append(path / "metadata.json")
    require(len(candidates) == 1, "Expected exactly one phase metadata file.")
    return candidates[0]


def phase_file(path: Path, logical_name: str) -> Path:
    metadata = read_json(metadata_path(path))
    name = metadata.get("files", {}).get(logical_name, logical_name)
    if logical_name == "delivery.json":
        name = (timestamped_name(logical_name, metadata["file_timestamp"])
                if "file_timestamp" in metadata else logical_name)
    else:
        require(name in metadata["hashes"], f"Missing evidence registration: {logical_name}.")
    require(Path(name).name == name and name not in ("", ".", ".."), "Invalid evidence file name.")
    return path / name


def commit_phase(directory: Path, phase: str, files: dict[str, list[dict[str, Any]]],
                 metadata: dict[str, Any]) -> Path:
    destination = directory / phase
    require(not destination.exists(), f"{phase} already exists; refusing to overwrite evidence.")
    finished = datetime.fromisoformat(metadata.get("finished_at") or stamp())
    require(finished.tzinfo is not None, "Evidence timestamp must include a timezone.")
    file_timestamp = finished.astimezone(KST).strftime("%Y%m%d_%H%M%S_KST")
    names = {name: timestamped_name(name, file_timestamp) for name in files}
    staging = Path(tempfile.mkdtemp(prefix=f"{phase}-pending-{file_timestamp}-", dir=directory))
    for filename, rows in files.items():
        write_jsonl(staging / names[filename], rows)
    if "verification.jsonl" in files:
        names["verification.csv"] = timestamped_name("verification.csv", file_timestamp)
        write_verification_csv(staging / names["verification.csv"], files["verification.jsonl"])
    metadata.update(file_timestamp=file_timestamp, files=names,
                    hashes={name: digest(staging / name) for name in names.values()})
    write_json(staging / timestamped_name("metadata.json", file_timestamp), metadata)
    os.rename(staging, destination)
    return destination


def verify_phase(path: Path) -> dict[str, Any]:
    manifest_path = metadata_path(path)
    metadata = read_json(manifest_path)
    require(isinstance(metadata.get("hashes"), dict), "Missing phase evidence hashes.")
    if "file_timestamp" in metadata:
        require(manifest_path.name == timestamped_name("metadata.json", metadata["file_timestamp"]),
                "Metadata filename/timestamp mismatch.")
        files = metadata.get("files")
        require(isinstance(files, dict) and set(files.values()) == set(metadata["hashes"])
                and len(files) == len(set(files.values())), "Invalid evidence file registration.")
        for logical_name, filename in files.items():
            require(filename == timestamped_name(logical_name, metadata["file_timestamp"]),
                    "Evidence filename/timestamp mismatch.")
    for name, expected in metadata["hashes"].items():
        require(Path(name).name == name and digest(path / name) == expected,
                "Evidence hash mismatch; refusing to continue.")
    return metadata


def batches(rows: list[dict[str, Any]], limit: int = 1024 * 1024) -> Iterator[bytes]:
    current: list[bytes] = []
    size = 2
    for row in rows:
        require(all(not isinstance(value, str) or len(value.encode("utf-8")) <= 30000
                    for value in row.values()), "Log field exceeds safe size.")
        encoded = canonical(row)
        require(len(encoded) + 2 <= limit, "Log record exceeds batch limit.")
        extra = len(encoded) + (1 if current else 0)
        if size + extra > limit:
            yield b"[" + b",".join(current) + b"]"
            current, size = [], 2
        size += len(encoded) + (1 if current else 0)
        current.append(encoded)
    if current:
        yield b"[" + b",".join(current) + b"]"


def log_headers(workspace_id: str, key: bytes, body: bytes, log_type: str,
                timestamp: str) -> dict[str, str]:
    message = f"POST\n{len(body)}\napplication/json\nx-ms-date:{timestamp}\n/api/logs"
    signature = base64.b64encode(hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest())
    return {"Authorization": f"SharedKey {workspace_id}:{signature.decode('ascii')}",
            "Content-Type": "application/json", "Log-Type": log_type,
            "x-ms-date": timestamp, "time-generated-field": "ObservedAt"}


def workspace_key(config: dict[str, Any]) -> bytes:
    raw = os.environ.get(config["workspace_key_env"]) or getpass.getpass("Workspace shared key: ")
    try:
        value = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise VerificationError("Workspace key must be valid Base64.") from None
    require(len(value) >= 16, "Workspace key is too short.")
    return value


def deliver(path: Path, config: dict[str, Any], key: bytes, wire: Wire) -> None:
    verify_phase(path)
    destination = {"workspace_id": config["workspace_id"], "log_type": config["log_type"]}
    checkpoint_path = phase_file(path, "delivery.json")
    checkpoint = read_json(checkpoint_path) if checkpoint_path.exists() else {
        **destination, "next_batch": 0, "accepted": False,
    }
    require(all(checkpoint.get(name) == value for name, value in destination.items()),
            "Log destination changed after delivery began.")
    payloads = list(batches(read_jsonl(phase_file(path, "events.jsonl"))))
    require(type(checkpoint.get("next_batch")) is int
            and 0 <= checkpoint["next_batch"] <= len(payloads), "Invalid delivery checkpoint.")
    url = f"https://{config['workspace_id']}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    for number in range(checkpoint["next_batch"], len(payloads)):
        body = payloads[number]
        for attempt in range(5):
            try:
                status, _ = wire.send("POST", url, log_headers(
                    config["workspace_id"], key, body, config["log_type"],
                    format_datetime(now().astimezone(timezone.utc), usegmt=True)), body)
                require(status == 200, "Log Analytics did not accept the batch.")
                break
            except HttpFailure as exc:
                if attempt == 4 or (exc.status not in (0, 429) and exc.status < 500):
                    raise
                time.sleep(max(exc.retry_after, min(30, 2 ** attempt)))
        checkpoint["next_batch"] = number + 1
        write_json(checkpoint_path, checkpoint)
    checkpoint["accepted"] = True
    checkpoint["accepted_at"] = stamp()
    write_json(checkpoint_path, checkpoint)


@contextlib.contextmanager
def run_lock(directory: Path) -> Iterator[None]:
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / ".lock"
    try:
        stream = lock.open("x", encoding="ascii")
    except FileExistsError:
        raise VerificationError("Run is locked; confirm no process is running before removing .lock.") from None
    try:
        with stream:
            stream.write(str(os.getpid()))
            stream.flush()
            yield
    finally:
        lock.unlink()


def contract(config: dict[str, Any]) -> dict[str, Any]:
    value = {field: config[field] for field in (
        "tenant_id", "excel_path", "sheet_name", "active_only",
        "workspace_id", "log_type",
    )}
    if config.get("_lab_resource_group_id"):
        value.update(lab_resource_group_id=config["_lab_resource_group_id"],
                     local_only=config["_local_only"])
    if config.get("_management_group_id"):
        value.update(management_group_id=config["_management_group_id"],
                     authorization_scope_filter="AtScopeAndBelow")
    return value


def execute(config: dict[str, Any], run_date: date | None = None, upload_only: bool = False,
            lab_resource_group_id: str | None = None, local_only: bool = False,
            before_file: Path | None = None, management_group: str | None = None) -> int:
    require(not local_only or bool(lab_resource_group_id),
            "--local-only is allowed only with --lab-resource-group.")
    require(not local_only or not upload_only, "--upload-only cannot be combined with --local-only.")
    require(not upload_only or before_file is not None, "--upload-only requires --before <A-file>.")
    require(management_group is None or lab_resource_group_id is None,
            "--management-group cannot be combined with --lab-resource-group.")
    require(management_group is not None or lab_resource_group_id is not None,
            "Production execution requires --management-group; lab execution requires --lab-resource-group.")
    config = dict(config)
    if management_group is not None:
        config["_management_group_id"] = management_group_id(management_group)
        print(f"Management group: {MG_PREFIX}{config['_management_group_id']} (this scope and below).",
              flush=True)
    event_context = ({"ManagementGroupScope": MG_PREFIX + config["_management_group_id"]}
                     if management_group is not None else {})
    if lab_resource_group_id is not None:
        scope = lab_scope(lab_resource_group_id)
        config.update(_lab_resource_group_id=scope, _local_only=local_only)
        print(f"LAB MODE: {scope}; immediate RG-only capture, NOT tenant-wide verification.",
              file=sys.stderr, flush=True)
    require(bool(config.get("workspace_id")) or local_only,
            "Workspace ID is required unless explicit lab local-only mode is used.")
    if before_file is not None:
        before_file = before_file.resolve()
        require(before_file.is_file() and before_file.parent.name == "before",
                "--before must identify a committed A file inside its original before folder.")
        selected_metadata = verify_phase(before_file.parent)
        require(before_file == phase_file(before_file.parent, "A.jsonl").resolve(),
                "--before must select the A file registered in the phase metadata.")
        baseline_date = date.fromisoformat(before_file.parent.parent.name)
        require(run_date is None or run_date == baseline_date, "--run-date does not match the A file.")
        run_date = baseline_date
        require(selected_metadata.get("run_date", run_date.isoformat()) == run_date.isoformat(),
                "Baseline date metadata mismatch.")
        directory = before_file.parent.parent
        require(directory == (Path(config["output_directory"]) / run_date.isoformat()).resolve(),
                "Selected A file is outside the configured output directory.")
    else:
        run_date = run_date or now().astimezone(KST).date()
        directory = Path(config["output_directory"]) / run_date.isoformat()
    wire = Wire()
    with run_lock(directory):
        before_path, after_path = directory / "before", directory / "after"
        require(before_file is not None or not before_path.exists(),
                "A baseline already exists. Specify --before <A-file> for comparison or upload retry.")
        require(before_file is None or before_path.exists(), "Selected baseline no longer exists.")
        baseline = verify_phase(before_path) if before_path.exists() else None
        if baseline:
            previous_contract = dict(baseline["contract"])
            previous_contract.pop("expected_subscription_ids", None)
            require(previous_contract == contract(config), "Baseline config contract changed.")
        require(not after_path.exists() or baseline is not None, "After evidence has no baseline.")
        completed = verify_phase(after_path) if after_path.exists() else None
        if completed:
            require(completed["run_id"] == baseline["run_id"], "Before/after run mismatch.")
            if "baseline_sha256" in completed:
                require(before_file is not None and completed["baseline_sha256"] == digest(before_file),
                        "Completed comparison refers to a different A file.")
        key = None if local_only else workspace_key(config)
        for path in (before_path, after_path):
            if path.exists() and key is not None:
                deliver(path, config, key, wire)
        if upload_only or completed:
            require(baseline is not None, "No evidence to upload.")
            print(f"Existing evidence {'preserved locally' if local_only else 'accepted by ingestion API'}: "
                  f"{directory}", flush=True)
            return completed["exit_code"] if completed else 0

        excel = Path(config["excel_path"])
        if baseline:
            require(digest(excel) == baseline["excel_sha256"], "Excel changed since baseline capture.")
            boundary = datetime.combine(run_date, wall_time(18), KST)
            require(lab_resource_group_id is not None or now() >= boundary,
                    "Before phase complete. Run again after deletion finishes.")
        else:
            require(run_date == now().astimezone(KST).date(), "Baseline must be captured today (KST).")
            boundary = datetime.combine(run_date, wall_time(18), KST)
            require(lab_resource_group_id is not None or now() < boundary,
                    "Too late to create a pre-deletion baseline.")
        auth = CliAuth(config["tenant_id"])
        azure = Azure(config, auth, wire)
        if baseline:
            assert before_file is not None
            require(auth.principal_id == baseline["principal_id"], "Baseline Entra user changed.")
            targets = read_jsonl(phase_file(before_path, "X.jsonl"))
            before_rows = read_jsonl(phase_file(before_path, "A.jsonl"))
            before = role_index(before_rows)
            previous = None
            capture = None
            for attempt in range(config["capture_attempts"]):
                capture = azure.capture()
                rows, scopes, started, finished = capture
                require(scopes == read_jsonl(phase_file(before_path, "scopes.jsonl")),
                        "Management group/subscription inventory changed; comparison rejected.")
                try:
                    azure.confirm(before, role_index(rows), targets)
                except NotConverged as exc:
                    print(str(exc), file=sys.stderr, flush=True)
                    previous = None
                else:
                    if previous == rows:
                        break
                    previous = rows
                if attempt + 1 < config["capture_attempts"]:
                    time.sleep(config["stability_seconds"])
            else:
                raise VerificationError("ARG/ARM did not converge; B was not committed. Retry later.")
            assert capture is not None
            rows, scopes, started, finished = capture
            deleted, results = compare(before_rows, rows, targets)
            counter = Counter(row["status"] for row in results)
            counts = {status: counter[status] for status in (
                "EXPECTED_DELETED", "EXPECTED_REMAINING", "NOT_IN_BASELINE", "UNEXPECTED_DELETED")}
            code = 2 if any(row["status"] != "EXPECTED_DELETED" for row in results) else 0
            run_id = baseline["run_id"]
            events = [event(run_id, "After", "Verification", **event_context, ObservedAt=finished,
                            Status=row["status"], TargetKey="target:" + row["targetKey"],
                            RoleAssignmentGuid=row["roleAssignmentId"],
                            RoleAssignmentId=row["assignmentId"],
                            DeletedNormally=row["deleted"],
                            DeletedUnexpectedly=row["unexpectedDeleted"],
                            NotDeleted=row["notDeleted"], DeletionResult=row["result"],
                            CurrentAssignmentId=row["currentAssignmentId"],
                            ExcelRows=",".join(map(str, row["excelRows"])),
                            PrincipalKey="principal:" + before.get(row["assignmentId"], {}).get(
                                "properties", {}).get("principalId", ""),
                            RoleDefinitionId=before.get(row["assignmentId"], {}).get(
                                "properties", {}).get("roleDefinitionId", ""))
                      for row in results]
            after = role_index(rows)
            summary = {"status": "REVIEW_REQUIRED" if code else "MATCHED", "counts": counts,
                       "before": len(before_rows), "after": len(rows), "deleted": len(deleted),
                       "added": len(set(after) - set(before)),
                       "modified": sum(role_identity(before[item]) != role_identity(after[item])
                                       for item in set(before) & set(after))}
            if lab_resource_group_id:
                summary.update(mode="LAB_RESOURCE_GROUP", scope=config["_lab_resource_group_id"],
                               log_analytics="NOT_SENT_LOCAL_ONLY" if local_only else "API_PENDING")
            elif management_group is not None:
                summary.update(mode="MANAGEMENT_GROUP",
                               management_group_id=config["_management_group_id"],
                               scope=MG_PREFIX + config["_management_group_id"])
            events.append(event(run_id, "After", "Summary", **event_context, ObservedAt=finished,
                                Status=summary["status"], BeforeCount=len(before_rows),
                                AfterCount=len(rows), DeletedCount=len(deleted),
                                AddedCount=summary["added"], ModifiedCount=summary["modified"],
                                CountsJson=json.dumps(counts, sort_keys=True)))
            path = commit_phase(directory, "after", {
                "B.jsonl": rows, "C.jsonl": deleted, "verification.jsonl": results,
                "events.jsonl": events, "summary.jsonl": [summary],
            }, {"run_id": run_id, "run_date": run_date.isoformat(),
                "baseline_file": str(before_file), "baseline_sha256": digest(before_file),
                "started_at": started, "finished_at": finished, "exit_code": code})
            print(json.dumps(summary, ensure_ascii=False), flush=True)
            print(f"B committed: {phase_file(path, 'B.jsonl')}", flush=True)
            print(f"Final results: {phase_file(path, 'verification.csv')}", flush=True)
        else:
            excel_hash = digest(excel)
            targets = load_targets(excel, config["sheet_name"], config["active_only"])
            require(digest(excel) == excel_hash, "Excel changed while being read.")
            prechecked_scopes = azure.check_scopes()
            preflight_checked_at = stamp()
            start = datetime.combine(run_date, wall_time(17, 59), KST)
            while not lab_resource_group_id and now() < start:
                print(f"Waiting for {start.isoformat()} (keep this PC awake).", flush=True)
                time.sleep(max(0, min(60, (start - now()).total_seconds())))
            require(lab_resource_group_id is not None or now() < boundary,
                    "Baseline capture missed the pre-deletion window.")
            rows, scopes, started, finished = azure.capture(prechecked_scopes)
            require(lab_resource_group_id is not None or now() < boundary,
                    "Baseline did not finish before 18:00; A was not committed.")
            index = role_index(rows)
            selected_ids = [key for row, key in resolved_targets(targets, index) if row["selected"]]
            missing = sum(item is None for item in selected_ids)
            if missing:
                print(f"WARNING: {missing} selected targets are absent from A; "
                      "their deletion cannot be proven.", file=sys.stderr, flush=True)
            require(len([item for item in selected_ids if item]) == len(set(
                item for item in selected_ids if item)), "Excel GUID/full-ID aliases duplicate a target.")
            run_id = ("lab-run-" if lab_resource_group_id else "run-") + str(uuid4())
            path = commit_phase(directory, "before", {
                "A.jsonl": rows, "X.jsonl": targets, "scopes.jsonl": scopes,
                "events.jsonl": [event(run_id, "Before", "Summary", **event_context, ObservedAt=finished,
                                       Status="BASELINE_CAPTURED", BeforeCount=len(rows),
                                       SelectedCount=len(selected_ids),
                                       MissingBaselineCount=missing)],
            }, {"run_id": run_id, "run_date": run_date.isoformat(),
                "principal_id": auth.principal_id, "contract": contract(config),
                "excel_sha256": excel_hash, "started_at": started, "finished_at": finished,
                "preflight_checked_at": preflight_checked_at,
                "baseline_deadline": None if lab_resource_group_id else boundary.isoformat()})
            code = 0
            print(f"A committed: {phase_file(path, 'A.jsonl')}", flush=True)
            print("After deletion finishes, run again with --before pointing to this A file.", flush=True)
        if key is not None:
            deliver(path, config, key, wire)
            print("Log Analytics HTTP 200: accepted, not yet query-verified.", flush=True)
        else:
            print("LAB LOCAL ONLY: events saved; Log Analytics NOT sent or verified.", flush=True)
        return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only daily Azure RBAC deletion verifier.")
    parser.add_argument("--config", type=Path, required=True)
    scope_options = parser.add_mutually_exclusive_group(required=True)
    scope_options.add_argument("--management-group",
                               help="Required for production: management group ID or ARM ID; descendants are discovered.")
    parser.add_argument("--before", type=Path,
                        help="Committed A JSONL path; required for comparison and upload retry.")
    parser.add_argument("--run-date", type=date.fromisoformat,
                        help="Optional KST date; must match --before if supplied.")
    parser.add_argument("--upload-only", action="store_true", help="Retry saved logs without recapture.")
    scope_options.add_argument("--lab-resource-group",
                               help="Lab alternative: tagged rg-ra-verifier-* ARM ID; RG-only immediate capture.")
    parser.add_argument("--local-only", action="store_true",
                        help="Lab only: save events locally without Workspace Key or log ingestion.")
    args = parser.parse_args(argv)
    print("WARNING: legacy Data Collector API support ended 2026-09-14; ingestion continues.",
          file=sys.stderr, flush=True)
    try:
        require(not args.local_only or bool(args.lab_resource_group),
                "--local-only requires --lab-resource-group.")
        config = load_config(args.config.resolve(), local_only=args.local_only)
        return execute(config, args.run_date, args.upload_only, args.lab_resource_group,
                       args.local_only, args.before, args.management_group)
    except (VerificationError, OSError, ValueError, KeyError, ImportError) as exc:
        if isinstance(exc, VerificationError):
            message = str(exc)
        else:
            message = f"{type(exc).__name__}; check input files, dependencies and saved evidence."
        print("ERROR: " + message, file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        print("Interrupted; committed evidence is preserved.", file=sys.stderr, flush=True)
        return 130


if __name__ == "__main__":
    sys.exit(main())
