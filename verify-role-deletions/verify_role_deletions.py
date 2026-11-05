from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

ARM = "https://management.azure.com"
MG_PREFIX = "/providers/Microsoft.Management/managementGroups/"
RA_MARKER = "/providers/microsoft.authorization/roleassignments/"
FIELDS = (
    "RoleAssignmentId", "ManagementGroupName", "SubscriptionName",
    "ResourceGroupName", "ResourceName", "RoleName", "Scope",
    "ScopeType", "ManagementGroupId", "SubscriptionId", "RoleDefinitionId",
    "PrincipalId",
)
ASSIGNMENTS_QUERY = """AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| project id, scope=tostring(properties.scope),
    roleDefinitionId=tostring(properties.roleDefinitionId),
    principalId=tostring(properties.principalId)
| order by id asc"""
ROLES_QUERY = """AuthorizationResources
| where type =~ 'microsoft.authorization/roledefinitions'
| project id, roleName=tostring(properties.roleName)
| order by id asc"""
SUBSCRIPTIONS_QUERY = """ResourceContainers
| where type =~ 'microsoft.resources/subscriptions'
| project id
| order by id asc"""


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def text(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"Missing/invalid {label}.")
    return value.strip()


def canonical(value: str) -> str:
    return value.strip().rstrip("/").lower()


def guid(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError:
        raise VerificationError(f"Invalid GUID: {value}") from None


def role_guid(value: str) -> str:
    require(bool(re.fullmatch(
        r"/(?:[^/?#]+/)*providers/microsoft\.authorization/roledefinitions/"
        r"[0-9a-f-]{36}", canonical(value)
    )), f"Invalid role definition ID: {value}")
    return guid(canonical(value).rsplit("/", 1)[-1])


def management_group(value: str) -> str:
    if value.lower().startswith(MG_PREFIX.lower()):
        value = value[len(MG_PREFIX):].rstrip("/")
    require(bool(re.fullmatch(r"[A-Za-z0-9_.()-]{1,90}", value)),
            "Use the management group ID (not display name) or its full ARM ID.")
    return value


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class AzureCLI:
    def __init__(self) -> None:
        self.executable = shutil.which("az")
        require(self.executable is not None, "Azure CLI not found. Install it and run az login.")
        assert self.executable is not None
        self.command = [self.executable]
        if Path(self.executable).suffix.lower() in (".cmd", ".bat"):
            interpreter = Path(self.executable).parent.parent / "python.exe"
            require(interpreter.is_file(),
                    "Cannot locate Azure CLI python.exe. Use the standard Azure CLI Windows installation.")
            # Bypass cmd.exe so URL ampersands and other arguments remain literal.
            self.command = [str(interpreter), "-IBm", "azure.cli"]

    def run(self, *args: str) -> dict[str, Any]:
        environment = dict(os.environ, PYTHONIOENCODING="utf-8", AZURE_CORE_NO_COLOR="true")
        try:
            result = subprocess.run(
                [*self.command, *args, "--output", "json", "--only-show-errors"],
                capture_output=True, encoding="utf-8", env=environment, timeout=180,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise VerificationError(f"Azure CLI failed: {type(exc).__name__}.") from exc
        require(result.returncode == 0,
                f"Azure CLI failed ({result.returncode}): {result.stderr.strip()[:2000]}")
        try:
            payload = json.loads(result.stdout)
        except (ValueError, UnicodeError) as exc:
            raise VerificationError("Azure CLI did not return valid JSON.") from exc
        require(isinstance(payload, dict), "Azure CLI returned a non-object response.")
        return payload

    def identity(self) -> dict[str, str]:
        account = self.run("account", "show")
        require(account.get("environmentName") == "AzureCloud",
                "Only Azure public cloud (AzureCloud) is supported.")
        user = account.get("user", {})
        require(user.get("type") == "user", "Run az login with an Entra user account.")
        return {
            "tenantId": guid(text(account.get("tenantId"), "tenantId")),
            "accountFingerprint": hashlib.sha256(
                text(user.get("name"), "user name").lower().encode("utf-8")
            ).hexdigest(),
        }

    def rest(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        require(path.startswith("/") and not path.startswith("//"), "Invalid ARM path.")
        args = ["rest", "--method", "get" if body is None else "post", "--url", ARM + path]
        if body is None:
            return self.run(*args)
        # A body file avoids cmd.exe quoting and command-line length limits on Windows.
        with tempfile.TemporaryDirectory(prefix="role-snapshot-") as directory:
            file = Path(directory) / "query.json"
            file.write_text(json.dumps(body), encoding="utf-8")
            return self.run(*args, "--headers", "Content-Type=application/json", "--body", f"@{file}")

    def hierarchy(self, group: str, tenant: str) -> dict[str, dict[str, str]]:
        payload = self.rest(
            f"{MG_PREFIX}{group}?api-version=2020-05-01&$expand=children&$recurse=true"
        )
        require(canonical(text(payload.get("id"), "root MG ID")) == canonical(MG_PREFIX + group),
                "Management group response does not match the requested ID.")
        require(canonical(text(payload.get("properties", {}).get("tenantId"), "MG tenant")) == tenant,
                "Management group tenant does not match az login.")
        return parse_hierarchy(payload)

    def query(self, group: str, query: str, scope_filter: str = "AtScopeAndBelow") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        ids: set[str] = set()
        tokens: set[str] = set()
        token: str | None = None
        expected: int | None = None
        while True:
            options: dict[str, Any] = {
                "$top": 1000, "resultFormat": "objectArray",
                "allowPartialScopes": False, "authorizationScopeFilter": scope_filter,
            }
            if token:
                options["$skipToken"] = token
            page = self.rest("/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01", {
                "managementGroups": [group], "query": query, "options": options,
            })
            data, count, total = page.get("data"), page.get("count"), page.get("totalRecords")
            require(isinstance(data, list), "ARG returned invalid data.")
            require(type(count) is int and count == len(data), "ARG page count mismatch.")
            require(type(total) is int and total >= 0, "ARG returned invalid totalRecords.")
            if expected is None:
                expected = total
            require(expected == total, "ARG totalRecords changed during paging. Retry the snapshot.")
            for row in data:
                require(isinstance(row, dict), "ARG returned an invalid row.")
                key = canonical(text(row.get("id"), "ARG id"))
                require(key not in ids, "ARG returned duplicate IDs. Retry the snapshot.")
                ids.add(key)
                rows.append(row)
            require(len(rows) <= total, "ARG returned more rows than totalRecords.")
            truncated = page.get("resultTruncated")
            require(truncated in (True, False, "true", "false"), "ARG omitted resultTruncated.")
            next_token = page.get("$skipToken")
            if next_token:
                require(isinstance(next_token, str) and next_token not in tokens and count > 0,
                        "ARG returned a repeated/invalid continuation token.")
                tokens.add(next_token)
                token = next_token
                continue
            require(truncated in (False, "false") and len(rows) == total,
                    "ARG results are incomplete; no snapshot was written.")
            return rows


def parse_hierarchy(payload: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}

    def visit(node: dict[str, Any], parent: str = "") -> None:
        key = canonical(text(node.get("id"), "hierarchy ID"))
        require(key not in result, "Duplicate hierarchy ID.")
        properties = node.get("properties", node)
        name = text(properties.get("displayName"), "hierarchy display name")
        if key.startswith(MG_PREFIX.lower()):
            require("/" not in key[len(MG_PREFIX):], "Invalid management group hierarchy ID.")
            kind = "ManagementGroup"
        else:
            require(bool(re.fullmatch(r"/subscriptions/[0-9a-f-]{36}", key)),
                    f"Unexpected hierarchy resource: {key}")
            guid(key.rsplit("/", 1)[-1])
            kind = "Subscription"
        result[key] = {"name": name, "parent": parent, "kind": kind}
        children = properties.get("children", [])
        require(isinstance(children, list), "Invalid hierarchy children.")
        for child in children:
            require(isinstance(child, dict), "Invalid hierarchy child.")
            visit(child, key)

    visit(payload)
    require(sum(item["kind"] == "Subscription" for item in result.values()) <= 10000,
            "ARG management-group queries support at most 10,000 subscriptions.")
    return result


def topology(hierarchy: dict[str, dict[str, str]]) -> dict[str, str]:
    return {key: value["parent"] for key, value in hierarchy.items()}


def assignment_row(
    assignment: dict[str, Any], hierarchy: dict[str, dict[str, str]], roles: dict[str, str],
) -> dict[str, str]:
    assignment_id = text(assignment.get("id"), "Role Assignment ID")
    parts = canonical(assignment_id).rsplit(RA_MARKER, 1)
    require(len(parts) == 2, f"Invalid Role Assignment ID: {assignment_id}")
    guid(parts[1])
    scope = text(assignment.get("scope"), "Role Assignment scope")
    key = canonical(scope)
    require(key == parts[0], f"Assignment ID/scope mismatch: {assignment_id}")
    role_id = text(assignment.get("roleDefinitionId"), "roleDefinitionId")
    role_name = roles.get(role_guid(role_id))
    if not role_name:
        raise VerificationError(f"Role name was not resolved: {role_id}")
    subscription_id, subscription_name, rg_name, resource_name = "", "", "", ""
    if key in hierarchy and hierarchy[key]["kind"] == "ManagementGroup":
        mg_id, scope_type = key, "ManagementGroup"
    else:
        segments = scope.strip("/").split("/")
        require(len(segments) >= 2 and segments[0].lower() == "subscriptions",
                f"Assignment is outside the management group hierarchy: {scope}")
        subscription_id = guid(segments[1])
        subscription_key = "/subscriptions/" + subscription_id
        require(subscription_key in hierarchy, f"Unknown subscription: {subscription_id}")
        subscription_name = hierarchy[subscription_key]["name"]
        mg_id = hierarchy[subscription_key]["parent"]
        scope_type = "Subscription"
        if len(segments) > 2:
            resource_start = 2
            if segments[2].lower() == "resourcegroups":
                require(len(segments) >= 4, f"Invalid resource group scope: {scope}")
                rg_name, scope_type, resource_start = segments[3], "ResourceGroup", 4
            if len(segments) > resource_start:
                require(segments[resource_start].lower() == "providers" and
                        len(segments) >= resource_start + 4, f"Invalid resource scope: {scope}")
                resource_name, scope_type = segments[-1], "Resource"
    require(mg_id in hierarchy, f"Unknown parent management group: {mg_id}")
    return dict(zip(FIELDS, (
        assignment_id, hierarchy[mg_id]["name"], subscription_name, rg_name, resource_name,
        role_name, scope, scope_type, mg_id[len(MG_PREFIX):], subscription_id, role_id,
        guid(text(assignment.get("principalId"), "principalId")),
    )))


def safe_cell(value: str) -> str:
    if value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return value


def metadata_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".metadata.json")


def assignment_key(value: str, scope: str) -> str:
    value = canonical(text(value, "RoleAssignmentId"))
    scope = canonical(text(scope, "Scope"))
    require(scope.startswith("/"), "Invalid snapshot scope.")
    if value.startswith("/"):
        parts = value.rsplit(RA_MARKER, 1)
        require(len(parts) == 2 and parts[0] == scope, "Invalid snapshot assignment ID.")
        value = parts[1]
    return scope + RA_MARKER + guid(value)


def save_csv(path: Path, rows: list[dict[str, str]], metadata: dict[str, Any]) -> None:
    companion = metadata_path(path)
    require(path.suffix.lower() == ".csv", "Output filename must end in .csv.")
    require(not path.exists() and not companion.exists(), "Output already exists; choose a new filename.")
    path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        assignment_id = assignment_key(row["RoleAssignmentId"], row["Scope"])
        output_row = dict(row, RoleAssignmentId=assignment_id.rsplit("/", 1)[-1])
        writer.writerow({key: safe_cell(output_row[key]) for key in FIELDS})
    data = buffer.getvalue().encode("utf-8-sig")
    metadata = dict(metadata, schemaVersion=2, rowCount=len(rows),
                    csvSha256=hashlib.sha256(data).hexdigest())
    # Exclusive creation preserves evidence. A failed/interrupted pair cannot pass load_csv.
    with path.open("xb") as file:
        file.write(data)
    with companion.open("x", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)
        file.write("\n")


def load_csv(path: Path) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    data = path.read_bytes()
    metadata = json.loads(metadata_path(path).read_text(encoding="utf-8"))
    require(isinstance(metadata, dict) and metadata.get("schemaVersion") in (1, 2) and
            metadata.get("kind") == "snapshot", "Input is not a supported snapshot.")
    require(metadata.get("csvSha256") == hashlib.sha256(data).hexdigest(),
            f"CSV checksum mismatch: {path}")
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
    require(reader.fieldnames == list(FIELDS), f"Snapshot CSV header mismatch: {path}")
    rows: dict[str, dict[str, str]] = {}
    for row in reader:
        require(set(row) == set(FIELDS) and all(isinstance(v, str) for v in row.values()),
                f"Malformed snapshot row: {path}")
        value = text(row.get("RoleAssignmentId"), "RoleAssignmentId")
        if metadata["schemaVersion"] == 1:
            require(value.startswith("/"), "Schema 1 requires a full Role Assignment ID.")
        else:
            guid(value)
        key = assignment_key(value, row["Scope"])
        require(key not in rows, f"Duplicate RoleAssignmentId in snapshot: {path}")
        row["RoleAssignmentId"] = key
        rows[key] = row
    require(metadata.get("rowCount") == len(rows), f"Snapshot row count mismatch: {path}")
    return rows, metadata


def snapshot(client: AzureCLI, group: str, output: Path) -> int:
    started = stamp()
    identity = client.identity()
    hierarchy = client.hierarchy(group, identity["tenantId"])
    subscriptions = {
        canonical(text(row.get("id"), "subscription ID"))
        for row in client.query(group, SUBSCRIPTIONS_QUERY)
    }
    expected = {key for key, value in hierarchy.items() if value["kind"] == "Subscription"}
    require(subscriptions == expected, "ARM hierarchy and ARG subscription coverage differ. Check access and retry.")
    assignments = client.query(group, ASSIGNMENTS_QUERY)
    roles: dict[str, str] = {}
    if assignments:
        for row in client.query(group, ROLES_QUERY, "AtScopeAboveAndBelow"):
            key = role_guid(text(row.get("id"), "role ID"))
            name = text(row.get("roleName"), "roleName")
            require(key not in roles or roles[key] == name, f"Conflicting role names: {key}")
            roles[key] = name
        for assignment in assignments:
            role_id = text(assignment.get("roleDefinitionId"), "roleDefinitionId")
            key = role_guid(role_id)
            if key not in roles:
                print(f"WARNING: ARG role name missing; resolving with ARM: {key}", file=sys.stderr)
                role = client.rest(role_id + "?api-version=2022-04-01")
                require(role_guid(text(role.get("id"), "ARM role ID")) == key, "ARM role ID mismatch.")
                roles[key] = text(role.get("properties", {}).get("roleName"), "ARM roleName")
    rows = [assignment_row(item, hierarchy, roles) for item in assignments]
    require(topology(client.hierarchy(group, identity["tenantId"])) == topology(hierarchy),
            "Management group hierarchy changed during collection. Retry.")
    require(client.identity() == identity, "Azure CLI identity changed during collection.")
    save_csv(output, sorted(rows, key=lambda row: canonical(row["RoleAssignmentId"])), {
        "kind": "snapshot", **identity, "managementGroupId": group.lower(),
        "startedAt": started, "completedAt": stamp(), "topology": topology(hierarchy),
        "authorizationScopeFilter": "AtScopeAndBelow",
    })
    print(f"Snapshot: {output} ({len(rows)} assignments)")
    print("WARNING: ARG reflects readable, indexed state, not an atomic backup. "
          "Keep read permissions unchanged; recheck absence with ARM/Activity Log.", file=sys.stderr)
    return 0


def diff(before: Path, after: Path, output: Path) -> int:
    old, old_meta = load_csv(before)
    new, new_meta = load_csv(after)
    for field in ("tenantId", "accountFingerprint", "managementGroupId", "topology", "authorizationScopeFilter"):
        require(field in old_meta and old_meta[field] == new_meta.get(field),
                f"Snapshots are not comparable: {field} differs or is missing.")
    try:
        old_start = datetime.fromisoformat(old_meta["startedAt"])
        old_end = datetime.fromisoformat(old_meta["completedAt"])
        new_start = datetime.fromisoformat(new_meta["startedAt"])
        new_end = datetime.fromisoformat(new_meta["completedAt"])
        require(all(value.tzinfo is not None for value in (old_start, old_end, new_start, new_end)),
                "Snapshot timestamps must include a timezone.")
        require(old_start <= old_end <= new_start <= new_end and old_start < new_start,
                "Use non-overlapping snapshots in chronological order.")
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError("Missing or invalid snapshot timestamps.") from exc
    deleted = [old[key] for key in sorted(old.keys() - new.keys())]
    save_csv(output, deleted, {
        "kind": "diff", "createdAt": stamp(), "before": str(before.resolve()),
        "after": str(after.resolve()), "beforeSha256": old_meta["csvSha256"],
        "afterSha256": new_meta["csvSha256"],
        "meaning": "Present before, absent after in ARG; not proof of deletion actor or cause.",
    })
    print(f"Removed from snapshot: {len(deleted)}; added: {len(new.keys() - old.keys())}; CSV: {output}")
    print("WARNING: Absence in ARG is a deletion candidate, not proof of a successful delete operation.",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only MG Role Assignment snapshots and CSV comparison.")
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("snapshot", help="Collect using the current az login user.")
    capture.add_argument("--management-group", required=True, help="MG ID or full ARM ID.")
    capture.add_argument("--output", required=True, type=Path, help="New .csv filename.")
    compare = commands.add_parser("diff", help="Compare local snapshots; no Azure login required.")
    compare.add_argument("--before", required=True, type=Path)
    compare.add_argument("--after", required=True, type=Path)
    compare.add_argument("--output", required=True, type=Path, help="New deleted-assignment .csv filename.")
    args = parser.parse_args(argv)
    try:
        if args.command == "snapshot":
            group = management_group(args.management_group)
            require(args.output.suffix.lower() == ".csv", "Output filename must end in .csv.")
            require(not args.output.exists() and not metadata_path(args.output).exists(),
                    "Output already exists; choose a new filename.")
            return snapshot(AzureCLI(), group, args.output)
        return diff(args.before, args.after, args.output)
    except (VerificationError, OSError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: Interrupted. Do not use any incomplete output pair.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())