#!/usr/bin/env python3
"""Filter, remove and restore Azure resource RBAC assignments without third-party modules."""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


RBAC_API = "2022-04-01"
PIM_API = "2020-10-01"
ARG_API = "2024-04-01"
MG_API = "2020-05-01"
KINDS = ("regular", "pim-eligible", "pim-timebound", "pim-activated")
PRINCIPAL_TYPES = (
    "User", "Group", "ServicePrincipal", "ManagedIdentity", "ForeignGroup",
    "Device", "AgentUser", "AgentServicePrincipal",
)
WRITABLE_PROPERTIES = (
    "principalId", "principalType", "roleDefinitionId", "description",
    "condition", "conditionVersion", "delegatedManagedIdentityResourceId",
)
PIM_READY = {"Provisioned", "Granted", "ScheduleCreated", "Accepted"}
PIM_TERMINAL = {"Revoked", "Canceled", "Denied", "Failed", "TimedOut", "Invalid"}


class SafetyError(Exception):
    """The requested operation cannot be performed safely."""


class ApiError(SafetyError):
    def __init__(self, status, code, message):
        self.status = status
        self.code = code
        super().__init__("HTTP {} {}: {}".format(status, code, message))


class JournalError(SafetyError):
    """A durable journal operation failed; no further mutations are allowed."""


class Reporter:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.last_progress = {}

    def emit(self, message):
        print(re.sub(r"[\x00-\x1f\x7f]", " ", str(message)), flush=True)

    def detail(self, message):
        if self.verbose:
            self.emit(message)

    def progress(self, stage, done, total=None):
        now = time.monotonic()
        if done == 1 or done == total or now - self.last_progress.get(stage, 0) >= 2:
            self.emit("{}: {}{}".format(stage, done, "/" + str(total) if total is not None else ""))
            self.last_progress[stage] = now


def utc_now():
    return datetime.now(timezone.utc)


def iso_time(value=None):
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Missing timezone")
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as error:
        raise SafetyError("Invalid timestamp in Azure response or journal.") from error


def cli_json(*arguments, timeout=60):
    executable = shutil.which("az")
    if not executable:
        raise SafetyError("Azure CLI is required. Use an authenticated Azure Cloud Shell session.")
    try:
        result = subprocess.run(
            [executable, *arguments, "--only-show-errors", "--output", "json"],
            capture_output=True, text=True, encoding="utf-8", timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError("Azure CLI could not complete the authentication/context command.") from error
    if result.returncode:
        raise SafetyError("Azure CLI authentication/context failed. Check your Cloud Shell sign-in and az account show.")
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        raise SafetyError("Azure CLI did not return valid JSON.") from error


def token_claims(token):
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, IndexError, TypeError):
        return {}


def retry_delay(headers, attempt):
    value = headers.get("Retry-After", "")
    try:
        delay = float(value)
    except (ValueError, TypeError):
        try:
            delay = (parsedate_to_datetime(value) - utc_now()).total_seconds()
        except (ValueError, TypeError, OverflowError):
            delay = 2 ** attempt
    return max(0, min(delay, 60))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise SafetyError("HTTP redirect refused; credentials are never forwarded to another URL.")


class AzureRestClient:
    def __init__(self, timeout=60, tenant_id=None, reporter=None):
        self.timeout = timeout
        self.reporter = reporter or Reporter()
        self.account = cli_json("account", "show", timeout=timeout)
        self.cloud_info = cli_json("cloud", "show", timeout=timeout)
        self.tenant = self.account.get("tenantId", "").casefold()
        self.cloud = self.cloud_info.get("name")
        if not self.tenant or not self.cloud or (tenant_id and tenant_id.casefold() != self.tenant):
            raise SafetyError("The current tenant/cloud does not match the requested context.")
        endpoints = self.cloud_info.get("endpoints", {})
        self.endpoints = {
            "arm": endpoints.get("resourceManager", "").rstrip("/"),
            "ms-graph": endpoints.get("microsoftGraphResourceId", "").rstrip("/"),
        }
        for endpoint in self.endpoints.values():
            parsed = urllib.parse.urlsplit(endpoint)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise SafetyError("Azure CLI returned an unsupported cloud endpoint.")
        self.tokens = {}
        self.token_lock = threading.Lock()
        self.allow_writes = False
        self.actor_id = None
        self.opener = urllib.request.build_opener(NoRedirect())

    def verify_context(self):
        account = cli_json("account", "show", timeout=self.timeout)
        cloud = cli_json("cloud", "show", timeout=self.timeout)
        if account.get("tenantId", "").casefold() != self.tenant or cloud.get("name") != self.cloud:
            raise SafetyError("Azure CLI tenant/cloud changed during this run.")

    def access_token(self, audience, refresh=False):
        with self.token_lock:
            cached = self.tokens.get(audience)
            if cached and not refresh and cached[1] > time.time() + 120:
                return cached[0]
            response = cli_json("account", "get-access-token", "--resource-type", audience, timeout=self.timeout)
            token = response.get("accessToken")
            if not token or response.get("tenant", "").casefold() != self.tenant:
                raise SafetyError("The token tenant does not match the fixed execution tenant.")
            claims = token_claims(token)
            if claims.get("tid", self.tenant).casefold() != self.tenant:
                raise SafetyError("Unexpected tenant in access token.")
            expires = response.get("expires_on", claims.get("exp", time.time() + 240))
            try:
                self.tokens[audience] = (token, float(expires))
            except (ValueError, TypeError) as error:
                raise SafetyError("Invalid token expiry.") from error
            if audience == "arm":
                actor = claims.get("oid")
                if self.actor_id and actor != self.actor_id:
                    raise SafetyError("The authenticated principal changed during this run.")
                self.actor_id = actor
            return token

    def request(self, method, path, body=None, audience="arm"):
        endpoint = self.endpoints[audience]
        url = endpoint + path if path.startswith("/") and not path.startswith("//") else path
        parsed = urllib.parse.urlsplit(url)
        expected = urllib.parse.urlsplit(endpoint)
        if (parsed.scheme != "https" or parsed.netloc.casefold() != expected.netloc.casefold()
                or parsed.username or parsed.password or parsed.fragment):
            raise SafetyError("Refusing a response/journal URL outside the current Azure endpoint.")
        readonly_post = method == "POST" and (
            (audience == "arm" and parsed.path.casefold() == "/providers/microsoft.resourcegraph/resources")
            or (audience == "ms-graph" and parsed.path == "/v1.0/$batch"
                and isinstance(body, dict) and all(item.get("method") == "GET" for item in body.get("requests", [])))
        )
        readonly = method == "GET" or readonly_post
        if not readonly and not self.allow_writes:
            raise SafetyError("Azure mutation blocked: no confirmed, durable execution plan.")
        refreshed = False
        for attempt in range(5):
            headers = {"Authorization": "Bearer " + self.access_token(audience), "Accept": "application/json"}
            payload = None
            if body is not None:
                payload = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(url, data=payload, headers=headers, method=method)
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    content = response.read()
                    return json.loads(content) if content else None
            except urllib.error.HTTPError as error:
                content = error.read()
                try:
                    details = json.loads(content).get("error", {})
                    code, message = details.get("code", ""), details.get("message", "Request failed.")
                except (ValueError, AttributeError):
                    code, message = "", "Azure returned a non-JSON error."
                if error.code == 401 and not refreshed:
                    self.access_token(audience, refresh=True)
                    refreshed = True
                    continue
                if attempt < 4 and error.code in (408, 429, 500, 502, 503, 504) and (readonly or error.code == 429):
                    self.reporter.emit("Retrying HTTP {} ({}/4).".format(error.code, attempt + 1))
                    time.sleep(retry_delay(error.headers, attempt))
                    continue
                raise ApiError(error.code, code, message) from error
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                if readonly and attempt < 4:
                    self.reporter.emit("Retrying a read after a connection error ({}/4).".format(attempt + 1))
                    time.sleep(2 ** attempt)
                    continue
                raise SafetyError("Connection failed; the outcome of a write, if attempted, is uncertain.") from error
            except ValueError as error:
                raise SafetyError("Azure returned invalid JSON; a write outcome may be uncertain.") from error
        raise SafetyError("Authentication retries exhausted.")

    def get_optional(self, path):
        try:
            return self.request("GET", path)
        except ApiError as error:
            if error.status == 404:
                return None
            raise

    def values(self, path):
        visited = set()
        while path:
            if path in visited:
                raise SafetyError("Repeated ARM nextLink; refusing an incomplete inventory.")
            visited.add(path)
            response = self.request("GET", path)
            if not isinstance(response, dict) or not isinstance(response.get("value"), list):
                raise SafetyError("ARM list response has no value array.")
            yield from response["value"]
            path = response.get("nextLink")


def api_path(resource_id, version, **query):
    parameters = {"api-version": version}
    parameters.update(query)
    return urllib.parse.quote(resource_id, safe="/") + "?" + urllib.parse.urlencode(parameters)


def entity_scope(resource_id, collection):
    marker = "/providers/microsoft.authorization/" + collection.casefold() + "/"
    if not isinstance(resource_id, str) or marker not in resource_id.casefold():
        raise SafetyError("Invalid authorization resource ID.")
    offset = resource_id.casefold().rfind(marker)
    name = resource_id[offset + len(marker):]
    try:
        if str(uuid.UUID(name)) != name.casefold():
            raise ValueError("Noncanonical assignment GUID")
    except ValueError as error:
        raise SafetyError("Invalid authorization resource GUID.") from error
    return normalize_scope(resource_id[:offset])


def validate_assignment(raw, collection="roleAssignments"):
    if not isinstance(raw, dict) or not isinstance(raw.get("properties"), dict):
        raise SafetyError("Incomplete assignment response.")
    scope = entity_scope(raw.get("id"), collection)
    properties = raw["properties"]
    if normalize_scope(properties.get("scope")) != scope:
        raise SafetyError("Assignment ID and properties.scope disagree.")
    try:
        uuid.UUID(properties["principalId"])
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise SafetyError("Missing/invalid principalId.") from error
    definition = properties.get("roleDefinitionId")
    if not isinstance(definition, str) or not re.search(
        r"/providers/microsoft\.authorization/roledefinitions/[0-9a-f-]{36}$", definition, re.IGNORECASE,
    ) or any(character in definition for character in "?#\\%"):
        raise SafetyError("Missing/invalid roleDefinitionId.")
    return scope


def resolve_scope(client, selection):
    if selection.kind != "management-group":
        return selection
    descendants = list(client.values(api_path(selection.root + "/descendants", MG_API)))
    parents = {}
    for descendant in descendants:
        identifier = normalize_scope(descendant.get("id"))
        parent = normalize_scope(descendant.get("properties", {}).get("parent", {}).get("id"))
        parents[identifier] = parent
    for identifier in parents:
        visited = set()
        cursor = identifier
        while cursor != selection.root:
            if cursor in visited or cursor not in parents:
                raise SafetyError("Management group descendant ancestry is incomplete.")
            visited.add(cursor)
            cursor = parents[cursor]
        if identifier.startswith("/subscriptions/") and len(identifier.split("/")) == 3:
            selection.subscriptions.add(identifier.split("/")[2])
        elif identifier.startswith("/providers/microsoft.management/managementgroups/"):
            selection.management_groups.add(identifier)
        else:
            raise SafetyError("Unexpected management group descendant type.")
    if len(selection.subscriptions) > 10000:
        raise SafetyError("More than 10,000 subscriptions: run explicit smaller scopes; partial ARG scopes are not allowed.")
    return selection


def arg_assignments(client, selection, filters, reporter):
    query = build_arg_query(selection, filters)
    reporter.detail("Generated ARG query: " + query)
    body = dict(selection.query_scope(), query=query, options={
        "authorizationScopeFilter": "AtScopeAndBelow", "allowPartialScopes": False,
        "resultFormat": "objectArray", "$top": 1000,
    })
    results, tokens = {}, set()
    expected_total = None
    page = 0
    while True:
        response = client.request("POST", api_path("/providers/Microsoft.ResourceGraph/resources", ARG_API), body)
        if not isinstance(response, dict) or not isinstance(response.get("data"), list):
            raise SafetyError("ARG did not return an objectArray.")
        if response.get("count") != len(response["data"]):
            raise SafetyError("ARG page count is inconsistent.")
        total = response.get("totalRecords")
        if not isinstance(total, int) or (expected_total is not None and total != expected_total):
            raise SafetyError("ARG inventory changed while paging; rerun discovery.")
        expected_total = total
        for assignment in response["data"]:
            identifier = assignment.get("id")
            entity_scope(identifier, "roleAssignments")
            results[identifier.casefold()] = assignment
        page += 1
        reporter.progress("ARG pages", page)
        token = response.get("$skipToken")
        if not token:
            if str(response.get("resultTruncated", "false")).casefold() == "true" or len(results) != total:
                raise SafetyError("ARG inventory is truncated/inconsistent; no assignments will be changed.")
            break
        if not response["data"] or token in tokens:
            raise SafetyError("ARG pagination made no progress.")
        tokens.add(token)
        body["options"]["$skipToken"] = token
    return list(results.values())


def arm_assignments(client, selection):
    if selection.kind == "management-group":
        scopes = sorted(selection.management_groups) + ["/subscriptions/" + item for item in sorted(selection.subscriptions)]
    else:
        scopes = [selection.root]
    results = {}
    for scope in scopes:
        query = {"$filter": "atScope()"} if scope.startswith("/providers/") else {}
        path = api_path(scope + "/providers/Microsoft.Authorization/roleAssignments", RBAC_API, **query)
        for raw in client.values(path):
            if not selection.contains(raw.get("properties", {}).get("scope")):
                continue
            validate_assignment(raw)
            results[raw["id"].casefold()] = raw
    return list(results.values())


def resolve_principals(client, properties_list, reporter):
    queries = {}
    for properties in properties_list:
        identifier = properties["principalId"].casefold()
        kind = properties.get("principalType", "")
        if kind in ("User", "AgentUser"):
            path = "/users/" + identifier + "?$select=id,displayName,mail,userPrincipalName"
        elif kind == "Group":
            path = "/groups/" + identifier + "?$select=id,displayName,mail"
        elif kind in ("ServicePrincipal", "AgentServicePrincipal"):
            path = "/servicePrincipals/" + identifier + "?$select=id,displayName,servicePrincipalType"
        else:
            path = "/directoryObjects/" + identifier
        queries[identifier] = path
    identifiers = list(queries)
    resolved = {}
    for offset in range(0, len(identifiers), 20):
        batch_ids = identifiers[offset:offset + 20]
        request = {"requests": [{"id": identifier, "method": "GET", "url": queries[identifier]} for identifier in batch_ids]}
        response = client.request("POST", "/v1.0/$batch", request, audience="ms-graph")
        if not isinstance(response, dict) or not isinstance(response.get("responses"), list):
            raise SafetyError("Graph batch response is incomplete.")
        items = {item.get("id"): item for item in response["responses"]}
        if len(items) != len(batch_ids) or set(items) != set(batch_ids):
            raise SafetyError("Graph batch response IDs do not match the requests.")
        for identifier in batch_ids:
            item = items[identifier]
            if item.get("status") in (429, 500, 502, 503, 504):
                time.sleep(retry_delay(item.get("headers", {}), 0))
                try:
                    value = client.request("GET", "/v1.0" + queries[identifier], audience="ms-graph")
                    item = {"status": 200, "body": value}
                except ApiError as error:
                    item = {"status": error.status}
            if item.get("status") == 200 and isinstance(item.get("body"), dict):
                value = item["body"]
                if value.get("id", "").casefold() != identifier:
                    raise SafetyError("Graph returned an unexpected principal ID.")
                resolved[identifier] = value
            else:
                resolved[identifier] = {"id": identifier, "resolutionError": "Graph HTTP " + str(item.get("status"))}
        reporter.progress("Principals resolved", min(offset + 20, len(identifiers)), len(identifiers))
    return resolved


def canonical_properties(properties):
    result = {key: properties.get(key) for key in WRITABLE_PROPERTIES}
    for key in ("principalId", "principalType", "delegatedManagedIdentityResourceId"):
        if isinstance(result[key], str):
            result[key] = result[key].casefold()
    if result["roleDefinitionId"]:
        result["roleDefinitionId"] = result["roleDefinitionId"].rsplit("/", 1)[-1].casefold()
    for key in ("description", "condition"):
        result[key] = result[key] or None
    if not result["condition"]:
        result["conditionVersion"] = None
    return result


def collection_for_route(route):
    collections = {"rbac": "roleAssignments", "assignment": "roleAssignmentSchedules", "eligibility": "roleEligibilitySchedules"}
    if route not in collections:
        raise SafetyError("Unknown assignment route in journal.")
    return collections[route]


@dataclass
class AssignmentRecord:
    raw: dict
    route: str = "rbac"
    kind: str = "regular"
    rbac: dict = field(default_factory=dict)
    instances: list = field(default_factory=list)
    principal: dict = field(default_factory=dict)
    projection: dict = field(default_factory=dict)

    @property
    def identifier(self):
        return self.raw["id"]

    @property
    def key(self):
        return self.route + ":" + self.identifier.casefold()

    @property
    def scope(self):
        return normalize_scope(self.raw["properties"]["scope"])

    @property
    def properties(self):
        result = dict(self.raw["properties"])
        if self.rbac:
            result["description"] = self.rbac["properties"].get("description")
        return result

    @property
    def end(self):
        if self.route == "rbac":
            return None
        values = [parse_time(item.get("properties", {}).get("endDateTime")) for item in [self.raw, *self.instances]]
        return min((value for value in values if value is not None), default=None)

    def restore_limitations(self):
        if self.kind == "pim-activated":
            return "Activation requires the principal to reactivate through PIM, including MFA/approval."
        if self.route != "rbac" and self.rbac and any(
            self.rbac["properties"].get(name) for name in ("description", "delegatedManagedIdentityResourceId")
        ):
            return "The PIM create API cannot restore the backing RBAC description/delegation fields."
        return ""

    def fingerprint(self):
        fields = (
            "scope", "assignmentType", "memberType", "status", "startDateTime", "endDateTime",
            "linkedRoleEligibilityScheduleId", "roleAssignmentScheduleId", "originRoleAssignmentId",
            "roleAssignmentScheduleRequestId", "roleEligibilityScheduleRequestId",
        )

        def relevant(raw):
            properties = raw.get("properties", {})
            return dict(canonical_properties(properties), **{key: properties.get(key) for key in fields})

        value = {
            "id": self.identifier.casefold(), "route": self.route, "kind": self.kind,
            "raw": relevant(self.raw), "rbac": relevant(self.rbac), "projection": relevant(self.projection),
            "instances": sorted((relevant(item) for item in self.instances), key=lambda item: json.dumps(item, sort_keys=True)),
        }
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()

    def snapshot(self):
        return dict(asdict(self), key=self.key, fingerprint=self.fingerprint())

    @classmethod
    def from_snapshot(cls, value):
        try:
            record = cls(**{key: value[key] for key in cls.__dataclass_fields__})
            validate_assignment(record.raw, collection_for_route(record.route))
            if record.kind not in KINDS:
                raise SafetyError("Unknown assignment kind in journal.")
            if record.route == "rbac" and record.kind != "regular":
                raise SafetyError("A PIM assignment cannot be restored using the RBAC route.")
            if record.rbac:
                if validate_assignment(record.rbac) != record.scope:
                    raise SafetyError("Backing RBAC scope differs from the PIM scope.")
                for name in ("principalId", "roleDefinitionId"):
                    if canonical_properties(record.rbac["properties"])[name] != canonical_properties(record.properties)[name]:
                        raise SafetyError("Backing RBAC principal/role differs from the PIM schedule.")
            if record.key != value["key"] or record.fingerprint() != value["fingerprint"]:
                raise SafetyError("Assignment snapshot integrity check failed.")
            return record
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            raise SafetyError("Malformed assignment snapshot.") from error


def pim_restore_body(record, now=None):
    now = now or utc_now()
    if record.route == "rbac" or record.kind == "pim-activated":
        raise SafetyError("This assignment does not support automatic PIM restoration.")
    start = parse_time(record.properties.get("startDateTime")) or now
    start = max(start, now)
    end = record.end
    if end and (end - start).total_seconds() < 300:
        raise SafetyError("PIM assignment expired or has less than five minutes of its original lifetime remaining.")
    properties = {key: record.properties[key] for key in ("principalId", "roleDefinitionId", "condition", "conditionVersion")
                  if record.properties.get(key) is not None}
    properties.update({
        "requestType": "AdminAssign",
        "justification": "Restore a role assignment removed by remove-roleassignments.py",
        "scheduleInfo": {
            "startDateTime": iso_time(start),
            "expiration": {"type": "AfterDateTime", "endDateTime": iso_time(end)} if end else {"type": "NoExpiration"},
        },
    })
    return {"properties": properties}


class RollbackJournal:
    def __init__(self, path, create=False):
        self.path = pathlib.Path(path).expanduser().resolve()
        self.sequence = 0
        self.valid_end = 0
        self.trailing_bytes = 0
        self.append_ready = create
        self.locked = False
        try:
            if create:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(str(self.path), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                self.file = os.fdopen(descriptor, "r+b")
            else:
                self.file = self.path.open("r+b")
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.locked = True
            except OSError:
                self.file.close()
                raise
        except OSError as error:
            raise JournalError("Cannot create/open/lock the rollback journal: " + str(self.path)) from error

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.close()

    def close(self):
        try:
            if self.locked:
                self.file.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        finally:
            self.locked = False
            self.file.close()

    def append(self, event, **data):
        if not self.append_ready:
            raise JournalError("Journal append has not been enabled.")
        row = dict(data, event=event, seq=self.sequence + 1, time=iso_time())
        payload = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        try:
            self.file.seek(0, os.SEEK_END)
            self.file.write(payload)
            self.file.flush()
            os.fsync(self.file.fileno())
        except OSError as error:
            raise JournalError("Journal write/fsync failed. Stop all mutations; reconcile the last recorded intent.") from error
        self.sequence += 1

    def read(self):
        rows = []
        self.file.seek(0)
        while True:
            line = self.file.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                self.trailing_bytes = len(line)
                break
            try:
                row = json.loads(line)
                if not isinstance(row, dict) or row.get("seq") != len(rows) + 1:
                    raise ValueError("Missing/out-of-order record")
            except (ValueError, UnicodeError) as error:
                raise JournalError("Corrupt journal record; refusing restoration.") from error
            rows.append(row)
            self.valid_end = self.file.tell()
        self.sequence = len(rows)
        if not rows or rows[0].get("event") != "header" or rows[0].get("schemaVersion") != 1:
            raise JournalError("Not a supported rollback journal.")
        return rows

    def prepare_append(self):
        if self.trailing_bytes:
            try:
                self.file.truncate(self.valid_end)
                self.file.flush()
                os.fsync(self.file.fileno())
            except OSError as error:
                raise JournalError("Cannot repair an incomplete trailing journal record.") from error
        self.append_ready = True
        if self.trailing_bytes:
            self.append("journal_recovery", discardedTrailingBytes=self.trailing_bytes)
            self.trailing_bytes = 0


def journal_path(args):
    drive = pathlib.Path.home() / "clouddrive"
    mounted_drive = drive.exists() and os.path.ismount(drive.resolve())
    if args.rollback_file:
        path = pathlib.Path(args.rollback_file).expanduser().resolve()
    else:
        base = drive if mounted_drive else pathlib.Path.cwd()
        label = "apply" if args.apply else "preview"
        path = base / ("role-assignment-{}-{}-{}.jsonl".format(label, utc_now().strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:8]))
    cloud_shell = any(name.startswith("ACC_") for name in os.environ) or bool(os.environ.get("CLOUD_SHELL"))
    persistent = mounted_drive and (path == drive.resolve() or drive.resolve() in path.parents)
    if cloud_shell and not persistent:
        if args.apply and not (args.allow_ephemeral_backup and args.rollback_file):
            raise JournalError("Use mounted ~/clouddrive for rollback, or explicitly set --rollback-file and --allow-ephemeral-backup.")
        print("WARNING: This Cloud Shell journal may be lost when the session ends.", file=sys.stderr)
    return path


def reference_id(scope, value, collection):
    if not isinstance(value, str) or not value:
        raise SafetyError("PIM response is missing a schedule reference.")
    if "/" not in value:
        try:
            value = scope + "/providers/Microsoft.Authorization/" + collection + "/" + str(uuid.UUID(value))
        except ValueError as error:
            raise SafetyError("Invalid PIM schedule reference.") from error
    entity_scope(value, collection)
    return value.casefold()


def same_assignment(left, right):
    left_properties = canonical_properties(left["properties"])
    right_properties = canonical_properties(right["properties"])
    return (normalize_scope(left["properties"]["scope"]) == normalize_scope(right["properties"]["scope"])
            and all(left_properties[name] == right_properties[name] for name in ("principalId", "roleDefinitionId")))


def pim_kind(raw, route, now=None):
    properties = raw["properties"]
    end = parse_time(properties.get("endDateTime"))
    now = now or utc_now()
    if properties.get("status") in PIM_TERMINAL or (end is not None and end <= now):
        return None
    if properties.get("status") not in PIM_READY or properties.get("memberType") != "Direct":
        raise SafetyError("PIM state cannot be classified safely: " + raw["id"])
    if route == "eligibility":
        return "pim-eligible"
    if properties.get("assignmentType") == "Activated":
        return "pim-activated"
    if properties.get("assignmentType") == "Assigned":
        return "pim-timebound" if end is not None else "regular"
    raise SafetyError("Unknown PIM assignmentType: " + raw["id"])


class PimInventory:
    def __init__(self, client, selection, reporter, include_eligible=False, assume_no_pim=False):
        if include_eligible and assume_no_pim:
            raise SafetyError("Cannot skip PIM checks when selecting PIM assignments.")
        self.client = client
        self.selection = selection
        self.reporter = reporter
        self.include_eligible = include_eligible
        self.assume_no_pim = assume_no_pim
        self.schedules = {}
        self.instances = {}
        self.eligibilities = {}
        self.exact_scopes = set()

    def roots(self):
        if self.selection.kind == "management-group":
            return sorted(self.selection.management_groups) + ["/subscriptions/" + item for item in sorted(self.selection.subscriptions)]
        return [self.selection.root]

    def load(self, scope, exact=False):
        scope = normalize_scope(scope)
        if self.assume_no_pim:
            if exact:
                self.exact_scopes.add(scope)
            return
        collections = [
            ("roleAssignmentSchedules", self.schedules),
            ("roleAssignmentScheduleInstances", self.instances),
        ]
        if self.include_eligible:
            collections.append(("roleEligibilitySchedules", self.eligibilities))
        for collection, target in collections:
            query = {"$filter": "atScope()"} if exact else {}
            try:
                rows = list(self.client.values(api_path(scope + "/providers/Microsoft.Authorization/" + collection, PIM_API, **query)))
            except ApiError as error:
                if error.code == "AadPremiumLicenseRequired":
                    raise SafetyError(
                        "PIM verification requires Entra ID P2/Governance (AadPremiumLicenseRequired). "
                        "No changes made. Only if you independently know this scope has no PIM assignments, "
                        "explicitly use --assume-no-pim for regular RBAC."
                    ) from error
                raise
            if exact:
                for identifier in list(target):
                    if normalize_scope(target[identifier]["properties"]["scope"]) == scope:
                        del target[identifier]
            for raw in rows:
                if raw.get("properties", {}).get("memberType") in ("Inherited", "Group"):
                    continue
                actual_scope = validate_assignment(raw, collection)
                if raw["properties"].get("memberType") != "Direct":
                    raise SafetyError("PIM memberType is missing/unknown; cannot prove this is a direct assignment.")
                if not exact or actual_scope == scope:
                    target[raw["id"].casefold()] = raw
        if exact:
            self.exact_scopes.add(scope)

    def load_hierarchy(self):
        if self.assume_no_pim:
            return
        roots = self.roots()
        for index, scope in enumerate(roots, 1):
            self.load(scope)
            self.reporter.progress("PIM inventory scopes", index, len(roots))

    def instances_for(self, schedule):
        result = []
        for instance in self.instances.values():
            if reference_id(instance["properties"]["scope"], instance["properties"].get("roleAssignmentScheduleId"), "roleAssignmentSchedules") == schedule["id"].casefold():
                if pim_kind(instance, "assignment") is not None:
                    result.append(instance)
        return result

    def from_schedule(self, schedule, route, backing=None):
        validate_assignment(schedule, collection_for_route(route))
        kind = pim_kind(schedule, route)
        if kind is None:
            return None
        instances = self.instances_for(schedule) if route == "assignment" else []
        for instance in instances:
            if not same_assignment(schedule, instance) or pim_kind(instance, "assignment") != kind:
                raise SafetyError("PIM schedule/instance identity, status or expiry classification is inconsistent.")
        if kind == "pim-activated" and len(instances) != 1:
            raise SafetyError("Expected exactly one direct activation instance; refusing an ambiguous removal.")
        backing = backing or {}
        if backing:
            validate_assignment(backing)
            if not same_assignment(schedule, backing):
                raise SafetyError("PIM schedule and backing role assignment disagree.")
            for name in ("condition", "conditionVersion"):
                if canonical_properties(schedule["properties"])[name] != canonical_properties(backing["properties"])[name]:
                    raise SafetyError("PIM schedule and backing role assignment conditions disagree.")
        return AssignmentRecord(schedule, route=route, kind=kind, rbac=backing, instances=instances)

    def classify(self, backing):
        scope = validate_assignment(backing)
        if scope not in self.exact_scopes:
            raise SafetyError("An exact-scope PIM check is required before classifying a role assignment.")
        related = [item for item in self.instances.values() if same_assignment(backing, item)]
        matches = [item for item in related if pim_kind(item, "assignment") is not None]
        schedules = [item for item in self.schedules.values()
                     if same_assignment(backing, item) and pim_kind(item, "assignment") is not None]
        if not matches:
            linked_history = any(reference_id(scope, item["properties"].get("originRoleAssignmentId"), "roleAssignments")
                                 == backing["id"].casefold() for item in related)
            if schedules or linked_history:
                raise SafetyError("A PIM schedule exists without a matching instance; rerun after provisioning completes.")
            return AssignmentRecord(backing)
        if len(matches) != 1:
            raise SafetyError("Multiple PIM instances match a role assignment.")
        instance = matches[0]
        origin = instance["properties"].get("originRoleAssignmentId")
        if reference_id(scope, origin, "roleAssignments") != backing["id"].casefold():
            raise SafetyError("The PIM instance does not prove the backing role assignment identity.")
        schedule_id = reference_id(scope, instance["properties"].get("roleAssignmentScheduleId"), "roleAssignmentSchedules")
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            raise SafetyError("The PIM instance's master schedule could not be read.")
        record = self.from_schedule(schedule, "assignment", backing)
        if record is None:
            raise SafetyError("An expired/revoked PIM assignment still has a backing RBAC assignment.")
        if record.kind == "regular" and not schedule["properties"].get("roleAssignmentScheduleRequestId"):
            return AssignmentRecord(backing, instances=[instance], projection=schedule)
        return record

    def linked_activations(self, eligibility):
        target = eligibility.identifier.rsplit("/", 1)[1].casefold()
        result = set()
        for raw in [*self.schedules.values(), *self.instances.values()]:
            properties = raw["properties"]
            link = properties.get("linkedRoleEligibilityScheduleId") or ""
            if link.rsplit("/", 1)[-1].casefold() != target:
                continue
            if pim_kind(raw, "assignment") is None:
                continue
            identifier = properties.get("roleAssignmentScheduleId", raw["id"])
            identifier = reference_id(properties["scope"], identifier, "roleAssignmentSchedules")
            result.add("assignment:" + identifier)
        return result


def get_live_assignment(client, identifier):
    entity_scope(identifier, "roleAssignments")
    raw = client.get_optional(api_path(identifier, RBAC_API))
    if raw is not None:
        validate_assignment(raw)
        if raw["id"].casefold() != identifier.casefold():
            raise SafetyError("ARM returned a different assignment ID than requested.")
    return raw


def discover_records(client, selection, filters, source, reporter, workers=4, assume_no_pim=False):
    if assume_no_pim and set(filters.assignment_kind) != {"regular"}:
        raise SafetyError("--assume-no-pim is only allowed with --assignment-kind regular.")
    resolve_scope(client, selection)
    candidates = arg_assignments(client, selection, filters, reporter) if source == "arg" else arm_assignments(client, selection)
    identifiers = sorted({raw["id"] for raw in candidates if selection.contains(entity_scope(raw["id"], "roleAssignments"))})
    reporter.emit("RBAC candidates: {}. Reading live properties and PIM state.".format(len(identifiers)))
    backing = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, raw in enumerate(pool.map(lambda identifier: get_live_assignment(client, identifier), identifiers), 1):
            if raw is not None:
                backing[raw["id"].casefold()] = raw
            reporter.progress("Live RBAC reads", index, len(identifiers))
    inventory = PimInventory(client, selection, reporter, "pim-eligible" in filters.assignment_kind, assume_no_pim)
    if assume_no_pim:
        reporter.emit("WARNING: Operator asserted this scope contains no PIM assignments. PIM exclusion is NOT verified.")
    inventory.load_hierarchy()
    exact_scopes = sorted({validate_assignment(raw) for raw in backing.values()})
    for index, scope in enumerate(exact_scopes, 1):
        inventory.load(scope, exact=True)
        if not assume_no_pim:
            reporter.progress("Exact-scope PIM checks", index, len(exact_scopes))
    records = {}
    for raw in backing.values():
        record = inventory.classify(raw)
        records[record.key] = record
    if any(kind != "regular" for kind in filters.assignment_kind):
        for route, schedules in (("assignment", inventory.schedules), ("eligibility", inventory.eligibilities)):
            for schedule in list(schedules.values()):
                if not selection.contains(schedule["properties"]["scope"]):
                    continue
                kind = pim_kind(schedule, route)
                if kind not in filters.assignment_kind:
                    continue
                key = route + ":" + schedule["id"].casefold()
                if key in records:
                    continue
                live_backing = None
                if route == "assignment":
                    origins = {reference_id(item["properties"]["scope"], item["properties"].get("originRoleAssignmentId"), "roleAssignments")
                               for item in inventory.instances_for(schedule)}
                    if len(origins) > 1:
                        raise SafetyError("A PIM schedule has multiple backing assignments; refusing a bulk removal.")
                    if origins:
                        identifier = next(iter(origins))
                        live_backing = backing.get(identifier) or get_live_assignment(client, identifier)
                record = inventory.from_schedule(schedule, route, live_backing)
                if record:
                    records[record.key] = record
    filtered = [record for record in records.values() if record.kind in filters.assignment_kind]
    if filters.needs_directory() or reporter.verbose:
        principals = resolve_principals(client, [record.properties for record in filtered], reporter)
        for record in filtered:
            record.principal = principals.get(record.properties["principalId"].casefold(), {})
    matched = [record for record in filtered if matches_filters(
        record.properties, filters, record.kind, record.principal, record.end,
    )]
    reporter.emit("Matched: {}. Excluded by kind/filters: {}.".format(len(matched), len(records) - len(matched)))
    return matched, inventory


def scope_document(selection):
    return {
        "kind": selection.kind, "root": selection.root, "include_children": selection.include_children,
        "management_groups": sorted(selection.management_groups), "subscriptions": sorted(selection.subscriptions),
    }


def scope_from_document(value):
    try:
        kind = value["kind"]
        if kind not in ("management-group", "subscription", "resource-group", "resource"):
            raise ValueError("Unknown scope kind")
        root = normalize_scope(value["root"])
        if (kind == "management-group") != root.startswith("/providers/"):
            raise ValueError("Scope kind/root mismatch")
        if not isinstance(value["include_children"], bool):
            raise ValueError("Invalid descendant setting")
        return ScopeSelection(kind, root, value["include_children"],
                              {normalize_scope(item) for item in value["management_groups"]},
                              {guid(item) for item in value["subscriptions"]})
    except (KeyError, TypeError, ValueError, argparse.ArgumentTypeError) as error:
        raise SafetyError("Malformed scope in rollback journal.") from error


def confirm_operation(args, operation, count, reporter, extra=""):
    if args.yes:
        return True
    if not sys.stdin.isatty():
        raise SafetyError("Interactive confirmation is unavailable. Review dry-run, then use --apply --yes explicitly.")
    expected = "{} {}".format(operation.upper(), count)
    reporter.emit("{} Type '{}' to confirm.".format(extra, expected))
    return input("> ").strip() == expected


def describe_record(record):
    return "{} | {} | {} | {}".format(
        record.kind, record.principal.get("displayName") or record.properties["principalId"],
        record.properties["roleDefinitionId"].rsplit("/", 1)[1], record.scope,
    )


def request_path(record, request_id):
    uuid.UUID(request_id)
    collection = "roleEligibilityScheduleRequests" if record.route == "eligibility" else "roleAssignmentScheduleRequests"
    return api_path(record.scope + "/providers/Microsoft.Authorization/" + collection + "/" + request_id, PIM_API)


def wait_pim_request(client, path, timeout, reporter):
    deadline = time.monotonic() + timeout
    while True:
        response = client.request("GET", path)
        status = response.get("properties", {}).get("status") if isinstance(response, dict) else None
        if status in ("Provisioned", "Granted", "ScheduleCreated", "Revoked"):
            return response
        if not status or status in PIM_TERMINAL:
            raise SafetyError("PIM request did not succeed: " + str(status))
        if time.monotonic() >= deadline:
            raise SafetyError("PIM request is still {}. Outcome is pending; consult the journal request ID.".format(status))
        reporter.detail("PIM request status: " + status)
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def removal_observed(client, record):
    version = RBAC_API if record.route == "rbac" else PIM_API
    current = client.get_optional(api_path(record.identifier, version))
    if record.route == "rbac":
        return current is None
    if current is not None:
        validate_assignment(current, collection_for_route(record.route))
        properties = current["properties"]
        expired = parse_time(properties.get("endDateTime"))
        if properties.get("status") not in ("Revoked", "Canceled") and not (expired and expired <= utc_now()):
            return False
    origins = {record.rbac["id"]} if record.rbac else set()
    if record.route == "assignment":
        path = api_path(record.scope + "/providers/Microsoft.Authorization/roleAssignmentScheduleInstances", PIM_API, **{"$filter": "atScope()"})
        for instance in client.values(path):
            properties = instance.get("properties", {})
            if properties.get("memberType") in ("Inherited", "Group"):
                continue
            identifier = reference_id(properties.get("scope"), properties.get("roleAssignmentScheduleId"), "roleAssignmentSchedules")
            if identifier != record.identifier.casefold():
                continue
            if pim_kind(instance, "assignment") is not None:
                return False
            if properties.get("originRoleAssignmentId"):
                origins.add(reference_id(record.scope, properties["originRoleAssignmentId"], "roleAssignments"))
    return all(get_live_assignment(client, identifier) is None for identifier in origins)


def wait_removed(client, record, timeout):
    deadline = time.monotonic() + timeout
    while not removal_observed(client, record):
        if time.monotonic() >= deadline:
            raise SafetyError("Deletion is not yet confirmed by ARM/PIM readback.")
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def refresh_record(client, record, inventory, filters=None):
    inventory.load(record.scope, exact=True)
    if record.route == "rbac":
        raw = get_live_assignment(client, record.identifier)
        if raw is None:
            return None
        current = inventory.classify(raw)
    else:
        raw = client.get_optional(api_path(record.identifier, PIM_API))
        if raw is None:
            return None
        validate_assignment(raw, collection_for_route(record.route))
        if raw["id"].casefold() != record.identifier.casefold():
            raise SafetyError("PIM returned an unexpected schedule ID.")
        backing = get_live_assignment(client, record.rbac["id"]) if record.rbac else None
        current = inventory.from_schedule(raw, record.route, backing)
        if current is None:
            return None
    if not inventory.selection.contains(current.scope):
        raise SafetyError("An assignment moved outside the selected scope.")
    if current.fingerprint() != record.fingerprint():
        raise SafetyError("Assignment/PIM state changed after backup; no change attempted: " + record.identifier)
    if filters and filters.needs_directory():
        resolved = resolve_principals(client, [current.properties], inventory.reporter)
        current.principal = resolved[current.properties["principalId"].casefold()]
    if filters and not matches_filters(current.properties, filters, current.kind, current.principal, current.end):
        raise SafetyError("Assignment no longer matches the requested filters.")
    return current


def fresh_linked_activations(client, record, reporter):
    scope = record.scope
    selection = ScopeSelection("management-group" if scope.startswith("/providers/") else "resource", scope,
                               management_groups={scope} if scope.startswith("/providers/") else set())
    resolve_scope(client, selection)
    inventory = PimInventory(client, selection, reporter)
    inventory.load_hierarchy()
    return inventory.linked_activations(record)


def pim_remove_body(record):
    properties = {
        "principalId": record.properties["principalId"], "roleDefinitionId": record.properties["roleDefinitionId"],
        "requestType": "AdminRemove", "justification": "Conditional bulk removal by remove-roleassignments.py",
    }
    target = "targetRoleEligibilityScheduleId" if record.route == "eligibility" else "targetRoleAssignmentScheduleId"
    properties[target] = record.identifier.rsplit("/", 1)[1]
    if record.kind == "pim-activated":
        if len(record.instances) != 1:
            raise SafetyError("Activation removal requires exactly one instance.")
        properties["targetRoleAssignmentScheduleInstanceId"] = record.instances[0]["id"].rsplit("/", 1)[1]
    return {"properties": properties}


def execute_delete(client, args, reporter):
    selection = scope_from_args(args)
    filters = FilterSpec.from_args(args)
    path = journal_path(args)
    reporter.emit("Tenant: {} | Cloud: {} | Mode: {}".format(client.tenant, client.cloud, "APPLY" if args.apply else "DRY RUN"))
    reporter.emit("Scope: " + selection.root)
    records, inventory = discover_records(client, selection, filters, args.source, reporter, args.read_workers, args.assume_no_pim)
    blocked = {}
    if records and args.apply and not client.actor_id and not args.allow_self_removal:
        raise SafetyError("Caller Object ID is unavailable; cannot enforce self-removal protection.")
    for record in records:
        if not args.allow_self_removal and client.actor_id and record.properties["principalId"].casefold() == client.actor_id.casefold():
            blocked[record.key] = "Caller direct assignment is protected (--allow-self-removal to override)."
        if record.restore_limitations() and not args.allow_nonrestorable_pim:
            blocked[record.key] = record.restore_limitations() + " Requires --allow-nonrestorable-pim."
    actionable_keys = {record.key for record in records} - set(blocked)
    for record in records:
        if record.route == "eligibility" and inventory.linked_activations(record) - actionable_keys:
            blocked[record.key] = "Linked activation is outside the confirmed removable set; eligibility removal blocked."
    actionable = [record for record in records if record.key not in blocked]
    actionable.sort(key=lambda record: (record.route == "eligibility", -record.scope.count("/"), record.key))
    reporter.emit("Removable: {} | Protected: {}".format(len(actionable), len(blocked)))
    for index, record in enumerate(records):
        if reporter.verbose or index < 10:
            reporter.emit(describe_record(record) + (" | PROTECTED: " + blocked[record.key] if record.key in blocked else ""))
    if len(records) > 10 and not reporter.verbose:
        reporter.emit("First 10 shown; the complete matching list is in the journal.")
    deleted, skipped, failed = 0, 0, 0
    with RollbackJournal(path, create=True) as journal:
        journal.append("header", schemaVersion=1, runId=str(uuid.uuid4()), mode="apply" if args.apply else "dry-run",
                       tenantId=client.tenant, cloud=client.cloud, callerId=client.actor_id,
                       selection=scope_document(selection), filters=asdict(filters), source=args.source,
                       pimCheck="operator-asserted-absent" if args.assume_no_pim else "verified")
        for record in records:
            journal.append("snapshot", key=record.key, record=record.snapshot(), blockedReason=blocked.get(record.key))
        journal.append("plan_complete", count=len(records), actionable=len(actionable))
        reporter.emit("Rollback journal: " + str(journal.path))
        if not args.apply or not actionable:
            reporter.emit("{}: matched={}, removable={}, protected={}, Azure mutations=0.".format(
                "DRY RUN" if not args.apply else "No removable assignments", len(records), len(actionable), len(blocked)))
            return 1 if args.apply and blocked else 0
        if not confirm_operation(args, "delete", len(actionable), reporter,
                                 "Keep a separate recovery operator authorized. PIM history cannot be restored."):
            journal.append("canceled")
            reporter.emit("Canceled. Azure mutations=0.")
            return 130
        client.verify_context()
        if selection.kind == "management-group":
            fresh = resolve_scope(client, ScopeSelection("management-group", selection.root, management_groups={selection.root}))
            if scope_document(fresh) != scope_document(selection):
                raise SafetyError("Management group hierarchy changed after discovery.")
        client.allow_writes = True
        try:
            for index, record in enumerate(actionable, 1):
                intent_written = False
                try:
                    current = refresh_record(client, record, inventory, filters)
                    if current is None:
                        skipped += 1
                        journal.append("delete_skipped", key=record.key, reason="Already missing/expired before mutation.")
                        continue
                    if record.route == "eligibility" and fresh_linked_activations(client, record, reporter):
                        raise SafetyError("A linked activation is still present; no eligibility removal attempted.")
                    request_id = str(uuid.uuid4()) if record.route != "rbac" else None
                    journal.append("delete_intent", key=record.key, requestId=request_id)
                    intent_written = True
                    if record.route == "rbac":
                        client.request("DELETE", api_path(record.identifier, RBAC_API))
                    else:
                        endpoint = request_path(record, request_id)
                        client.request("PUT", endpoint, pim_remove_body(record))
                        wait_pim_request(client, endpoint, args.poll_timeout, reporter)
                    wait_removed(client, record, args.poll_timeout)
                    journal.append("delete_success", key=record.key)
                    deleted += 1
                    reporter.progress("Deleted", index, len(actionable))
                except JournalError:
                    raise
                except (SafetyError, OSError) as error:
                    failed += 1
                    known_rejection = isinstance(error, ApiError) and error.status in (400, 401, 403, 404, 409, 422, 429)
                    event = "delete_uncertain" if intent_written and not known_rejection else "delete_failure"
                    journal.append(event, key=record.key, error=str(error))
                    reporter.emit("STOP: " + str(error))
                    break
            journal.append("delete_summary", deleted=deleted, skipped=skipped, failed=failed,
                           protected=len(blocked), unprocessed=len(actionable) - deleted - skipped - failed)
        finally:
            client.allow_writes = False
    reporter.emit("Result: deleted={}, skipped={}, failed={}, protected={}, unprocessed={}.".format(
        deleted, skipped, failed, len(blocked), len(actionable) - deleted - skipped - failed))
    reporter.emit("Rollback journal: " + str(path))
    return 1 if failed or blocked else 0


def journal_state(rows):
    header = rows[0]
    if header.get("mode") != "apply":
        raise SafetyError("A dry-run/preview journal cannot be used to create role assignments.")
    selection = scope_from_document(header.get("selection"))
    snapshots, states = {}, {}
    complete = False
    metadata_events = {"header", "journal_recovery", "canceled", "delete_summary", "rollback_summary"}
    for row in rows:
        event = row.get("event")
        if event == "snapshot":
            if complete:
                raise JournalError("Snapshots cannot be added after plan_complete.")
            record = AssignmentRecord.from_snapshot(row.get("record", {}))
            if row.get("key") != record.key or record.key in snapshots or not selection.contains(record.scope):
                raise JournalError("Duplicate/out-of-scope assignment in journal.")
            snapshots[record.key] = record
            states[record.key] = {"deletion": "unattempted", "blocked": bool(row.get("blockedReason")), "restore": None,
                                  "delete_intent": None, "rollback_intent": None}
        elif event == "plan_complete":
            if complete or row.get("count") != len(snapshots):
                raise JournalError("Journal plan is incomplete or duplicated.")
            complete = True
        elif event in metadata_events:
            continue
        else:
            key = row.get("key")
            if not complete or key not in states:
                raise JournalError("Mutation record has no complete source snapshot.")
            state = states[key]
            if event == "delete_intent":
                if state["blocked"] or state["delete_intent"] is not None:
                    raise JournalError("Invalid or duplicated delete intent.")
                state["delete_intent"] = row
                state["deletion"] = "pending"
            elif event in ("delete_success", "delete_uncertain"):
                if state["delete_intent"] is None:
                    raise JournalError("Deletion result without a preceding intent.")
                state["deletion"] = "deleted" if event == "delete_success" else "pending"
            elif event == "delete_failure":
                state["deletion"] = "failed"
            elif event == "delete_skipped":
                state["deletion"] = "skipped"
            elif event == "rollback_intent":
                if state["deletion"] not in ("deleted", "pending"):
                    raise JournalError("Attempted restore of an assignment that was not deleted.")
                state["rollback_intent"] = row
            elif event == "rollback_result":
                state["restore"] = row
            else:
                raise JournalError("Unknown journal event: " + str(event))
    if not complete:
        raise JournalError("No completed backup plan; automatic restoration is refused.")
    return header, selection, snapshots, states


def equivalent_pim(record, current):
    validate_assignment(current, collection_for_route(record.route))
    if not same_assignment(record.raw, current) or pim_kind(current, record.route) != record.kind:
        return False
    for name in ("condition", "conditionVersion"):
        if canonical_properties(record.properties)[name] != canonical_properties(current["properties"])[name]:
            return False
    if parse_time(current["properties"].get("endDateTime")) != record.end:
        return False
    original_start = parse_time(record.properties.get("startDateTime"))
    current_start = parse_time(current["properties"].get("startDateTime"))
    if original_start is not None:
        if current_start is None or current_start < original_start:
            return False
        if original_start > utc_now() and original_start != current_start:
            return False
        if original_start <= utc_now() < current_start:
            return False
    return True


def wait_restored(client, record, identifier, timeout):
    version = RBAC_API if record.route == "rbac" else PIM_API
    if entity_scope(identifier, collection_for_route(record.route)) != record.scope:
        raise SafetyError("Restored assignment target is outside the original scope.")
    deadline = time.monotonic() + timeout
    while True:
        current = client.get_optional(api_path(identifier, version))
        if current:
            validate_assignment(current, collection_for_route(record.route))
            if current["id"].casefold() != identifier.casefold():
                raise SafetyError("Restore GET returned a different assignment ID.")
            matches = (same_assignment(record.raw, current)
                       and canonical_properties(record.properties) == canonical_properties(current["properties"])) if record.route == "rbac" else equivalent_pim(record, current)
            if matches:
                return current
            if record.route == "rbac" or current["properties"].get("status") in PIM_READY | PIM_TERMINAL:
                raise SafetyError("Restored assignment properties do not match the backup.")
        if time.monotonic() >= deadline:
            raise SafetyError("Restoration has not been confirmed by live readback.")
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def target_from_request(record, response):
    name = "targetRoleEligibilityScheduleId" if record.route == "eligibility" else "targetRoleAssignmentScheduleId"
    return reference_id(record.scope, response.get("properties", {}).get(name), collection_for_route(record.route))


def existing_restore(client, record, prior_intent, args, reporter):
    if record.route == "rbac":
        current = get_live_assignment(client, record.identifier)
        if current:
            if canonical_properties(current["properties"]) != canonical_properties(record.properties):
                raise SafetyError("Existing assignment conflicts with the backup; refusing to overwrite it.")
            return current, None
        path = api_path(record.scope + "/providers/Microsoft.Authorization/roleAssignments", RBAC_API, **{"$filter": "atScope()"})
        for other in client.values(path):
            other_scope = other.get("properties", {}).get("scope")
            if other_scope == "/" or normalize_scope(other_scope) != record.scope:
                continue
            validate_assignment(other)
            if same_assignment(record.raw, other):
                raise SafetyError("Another assignment already grants this principal/role/scope with a different ID.")
        return None, None
    retry_id = None
    if prior_intent and prior_intent.get("requestId"):
        retry_id = guid(prior_intent["requestId"])
        endpoint = request_path(record, retry_id)
        response = client.get_optional(endpoint)
        if response:
            status = response.get("properties", {}).get("status")
            if status in PIM_TERMINAL:
                retry_id = None
            else:
                if status not in PIM_READY - {"Accepted"}:
                    response = wait_pim_request(client, endpoint, args.poll_timeout, reporter)
                target = target_from_request(record, response)
                return wait_restored(client, record, target, args.poll_timeout), None
    path = api_path(record.scope + "/providers/Microsoft.Authorization/" + collection_for_route(record.route), PIM_API, **{"$filter": "atScope()"})
    matches = []
    for current in client.values(path):
        if current.get("properties", {}).get("memberType") in ("Inherited", "Group"):
            continue
        validate_assignment(current, collection_for_route(record.route))
        if not same_assignment(record.raw, current) or pim_kind(current, record.route) is None:
            continue
        if not equivalent_pim(record, current):
            raise SafetyError("An existing PIM schedule conflicts with the original type, condition or lifetime.")
        matches.append(current)
    if len(matches) > 1:
        raise SafetyError("Multiple existing PIM schedules match this restoration.")
    return (matches[0] if matches else None), retry_id


def restore_record(client, record, state, args, reporter, journal):
    completed = {"restored", "restored_with_limitations", "already_present"}
    if state["restore"] and state["restore"].get("status") in completed:
        if record.restore_limitations():
            reporter.emit("PARTIAL: Previously restored permissions still have these limitations: " + record.restore_limitations())
            return "previously_restored_with_limitations"
        return "previously_restored"
    if record.kind == "pim-activated":
        reporter.emit("MANUAL: {} | {}".format(describe_record(record), record.restore_limitations()))
        return "manual_required"
    body = None
    if record.route != "rbac":
        if record.end and (record.end - max(parse_time(record.properties.get("startDateTime")) or utc_now(), utc_now())).total_seconds() < 300:
            reporter.emit("EXPIRED: Original PIM lifetime cannot be restored: " + record.identifier)
            return "expired"
        body = pim_restore_body(record)
    current, retry_id = existing_restore(client, record, state["rollback_intent"], args, reporter)
    if current:
        status = "restored_with_limitations" if record.restore_limitations() else "already_present"
        if args.apply:
            journal.append("rollback_result", key=record.key, status=status, restoredId=current["id"])
        return status
    if not args.apply:
        reporter.detail("Would restore: " + describe_record(record))
        return "would_restore"
    request_id = retry_id or str(uuid.uuid4()) if record.route != "rbac" else None
    journal.append("rollback_intent", key=record.key, requestId=request_id)
    if record.route == "rbac":
        properties = {name: record.properties[name] for name in WRITABLE_PROPERTIES if record.properties.get(name) is not None}
        client.request("PUT", api_path(record.identifier, RBAC_API), {"properties": properties})
        target = record.identifier
    else:
        endpoint = request_path(record, request_id)
        client.request("PUT", endpoint, body)
        response = wait_pim_request(client, endpoint, args.poll_timeout, reporter)
        target = target_from_request(record, response)
    current = wait_restored(client, record, target, args.poll_timeout)
    status = "restored_with_limitations" if record.restore_limitations() else "restored"
    journal.append("rollback_result", key=record.key, status=status, restoredId=current["id"])
    if record.restore_limitations():
        reporter.emit("PARTIAL: " + record.restore_limitations())
    return status


def execute_rollback(args, reporter, client=None):
    path = journal_path(args)
    with RollbackJournal(path) as journal:
        rows = journal.read()
        header, selection, snapshots, states = journal_state(rows)
        if header.get("pimCheck") == "operator-asserted-absent":
            reporter.emit("WARNING: The original deletion used --assume-no-pim; its PIM exclusion was not independently verified.")
        if journal.trailing_bytes:
            reporter.emit("WARNING: An incomplete trailing journal record was ignored. Pending intents are not assumed successful.")
        client = client or AzureRestClient(args.timeout, args.tenant_id, reporter)
        if header.get("tenantId", "").casefold() != client.tenant or header.get("cloud") != client.cloud:
            raise SafetyError("Rollback tenant/cloud does not match the authenticated context.")
        if args.tenant_id and args.tenant_id.casefold() != client.tenant:
            raise SafetyError("--tenant-id does not match the authenticated context.")
        if selection.kind == "management-group":
            selection = resolve_scope(client, ScopeSelection("management-group", selection.root, management_groups={selection.root}))
        candidates = []
        pending = 0
        for key, record in snapshots.items():
            state = states[key]
            if state["deletion"] not in ("deleted", "pending"):
                continue
            if not selection.contains(record.scope):
                raise SafetyError("A restore target is no longer inside the original scope hierarchy.")
            if state["deletion"] == "pending":
                if not args.reconcile_pending:
                    pending += 1
                    reporter.emit("PENDING (not auto-restored): " + record.identifier)
                    continue
                if record.route != "rbac":
                    request_id = (state["delete_intent"] or {}).get("requestId")
                    if not request_id:
                        raise JournalError("PIM delete intent is missing its request ID.")
                    endpoint = request_path(record, guid(request_id))
                    response = client.get_optional(endpoint)
                    if not response or response.get("properties", {}).get("status") in PIM_TERMINAL - {"Revoked"}:
                        pending += 1
                        reporter.emit("PENDING: PIM removal request cannot prove a successful deletion: " + record.identifier)
                        continue
                    wait_pim_request(client, endpoint, args.poll_timeout, reporter)
                if not removal_observed(client, record):
                    pending += 1
                    reporter.emit("PENDING: Removal is not observable; no automatic restore: " + record.identifier)
                    continue
            candidates.append(record)
        candidates.sort(key=lambda record: (record.route != "eligibility", record.scope.count("/"), record.key))
        reporter.emit("Rollback | Tenant: {} | Mode: {} | Candidates: {} | Unresolved: {}".format(
            client.tenant, "APPLY" if args.apply else "DRY RUN", len(candidates), pending))
        counts = {"unresolved": pending}
        if args.apply and candidates:
            if not confirm_operation(args, "restore", len(candidates), reporter,
                                     "Reconciled pending deletions may have an uncertain original cause." if args.reconcile_pending else ""):
                reporter.emit("Canceled. No Azure mutations.")
                return 130
            client.verify_context()
            journal.prepare_append()
            client.allow_writes = True
        try:
            for index, record in enumerate(candidates, 1):
                try:
                    status = restore_record(client, record, states[record.key], args, reporter, journal)
                    counts[status] = counts.get(status, 0) + 1
                    if args.apply and status in ("manual_required", "expired"):
                        journal.append("rollback_result", key=record.key, status=status)
                    reporter.progress("Rollback checked", index, len(candidates))
                except JournalError:
                    raise
                except (SafetyError, OSError) as error:
                    counts["failed"] = counts.get("failed", 0) + 1
                    if args.apply:
                        journal.append("rollback_result", key=record.key, status="failed_or_uncertain", error=str(error))
                    reporter.emit("STOP: " + str(error))
                    break
            if args.apply and candidates:
                journal.append("rollback_summary", counts=counts)
        finally:
            client.allow_writes = False
        reporter.emit("Rollback result: " + ", ".join("{}={}".format(key, value) for key, value in sorted(counts.items())))
        reporter.emit("Journal: " + str(path))
        return 1 if any(counts.get(key) for key in (
            "unresolved", "failed", "manual_required", "expired", "restored_with_limitations", "previously_restored_with_limitations",
        )) else 0


def nonempty(value):
    if not value.strip():
        raise argparse.ArgumentTypeError("An empty filter is not allowed.")
    return value


def guid(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError) as error:
        raise argparse.ArgumentTypeError("Expected an object/subscription GUID.") from error


def principal_type(value):
    key = re.sub(r"[ _-]", "", value).casefold()
    for candidate in PRINCIPAL_TYPES:
        if candidate.casefold() == key:
            return candidate
    raise argparse.ArgumentTypeError("Unknown principal type: " + value)


def normalize_scope(value):
    if not isinstance(value, str):
        raise SafetyError("Scope must be an ARM ID.")
    value = value.strip().rstrip("/")
    if (not value.startswith("/") or "//" in value
            or any(character in value for character in "?#\\%")
            or any(ord(character) < 32 for character in value)
            or any(segment in (".", "..", "") for segment in value.split("/")[1:])):
        raise SafetyError("Invalid ARM scope: " + value)
    value = re.sub(
        r"^/providers/microsoft\.subscription/subscriptions/", "/subscriptions/",
        value, flags=re.IGNORECASE,
    )
    if not re.match(
        r"^/(subscriptions/[0-9a-f-]{36}(?:/|$)|providers/microsoft\.management/managementgroups/[^/]+$)",
        value, re.IGNORECASE,
    ):
        raise SafetyError("Expected a subscription, resource group, resource or management group scope.")
    if value.casefold().startswith("/subscriptions/"):
        try:
            uuid.UUID(value.split("/")[2])
        except ValueError as error:
            raise SafetyError("Invalid subscription ID in scope.") from error
    return value.casefold()


def is_below(scope, parent):
    return scope == parent or scope.startswith(parent + "/")


@dataclass
class ScopeSelection:
    kind: str
    root: str
    include_children: bool = True
    management_groups: set = field(default_factory=set)
    subscriptions: set = field(default_factory=set)

    def contains(self, scope):
        if scope == "/":
            return False
        scope = normalize_scope(scope)
        if self.kind == "management-group":
            if scope in self.management_groups or scope == self.root:
                return True
            return any(is_below(scope, "/subscriptions/" + item) for item in self.subscriptions)
        return is_below(scope, self.root) if self.include_children else scope == self.root

    def query_scope(self):
        if self.kind == "management-group":
            return {"managementGroups": [self.root.rsplit("/", 1)[1]]}
        return {"subscriptions": [self.root.split("/")[2]]}


def scope_from_args(args):
    if args.management_group:
        if args.resource_group:
            raise SafetyError("--resource-group requires --subscription, not --management-group.")
        root = normalize_scope("/providers/Microsoft.Management/managementGroups/" + args.management_group)
        result = ScopeSelection("management-group", root, management_groups={root})
    elif args.subscription:
        root = "/subscriptions/" + args.subscription
        kind = "subscription"
        if args.resource_group:
            if "/" in args.resource_group:
                raise SafetyError("--resource-group must be a name, not an ARM ID.")
            root += "/resourceGroups/" + args.resource_group
            kind = "resource-group"
        result = ScopeSelection(kind, normalize_scope(root))
    else:
        if args.resource_group:
            raise SafetyError("--resource-group requires --subscription.")
        root = normalize_scope(args.resource_id)
        if "/providers/" not in root or not root.startswith("/subscriptions/"):
            raise SafetyError("--resource-id must identify a resource, not a container scope.")
        result = ScopeSelection("resource", root, args.include_resource_descendants)
    if args.include_resource_descendants and not args.resource_id:
        raise SafetyError("--include-resource-descendants requires --resource-id.")
    return result


@dataclass
class FilterSpec:
    description_contains: tuple = ()
    principal_id: tuple = ()
    principal_type: tuple = ()
    principal_name: tuple = ()
    principal_name_contains: tuple = ()
    principal_email: tuple = ()
    assignment_kind: tuple = ("regular",)
    expiration: str = "any"

    @classmethod
    def from_args(cls, args):
        values = {}
        for name in cls.__dataclass_fields__:
            value = getattr(args, name)
            values[name] = value if name == "expiration" else tuple(value or ())
        values["assignment_kind"] = values["assignment_kind"] or ("regular",)
        return cls(**values)

    def needs_directory(self):
        return bool(self.principal_name or self.principal_name_contains or self.principal_email
                    or {"ServicePrincipal", "ManagedIdentity"}.intersection(self.principal_type))


def matches_filters(properties, filters, kind="regular", principal=None, end=None):
    if kind not in filters.assignment_kind:
        return False
    if filters.expiration != "any" and (end is not None) != (filters.expiration == "time-bound"):
        return False
    principal = principal or {}
    original_type = properties.get("principalType", "")
    effective_type = original_type
    if original_type == "ServicePrincipal" and filters.principal_type:
        subtype = principal.get("servicePrincipalType")
        if {"ServicePrincipal", "ManagedIdentity"}.intersection(filters.principal_type):
            if subtype not in ("ManagedIdentity", "Application", "Legacy"):
                raise SafetyError("Cannot distinguish a managed identity from an application service principal.")
            effective_type = "ManagedIdentity" if subtype == "ManagedIdentity" else "ServicePrincipal"
    if filters.principal_type and effective_type not in filters.principal_type:
        return False
    if filters.principal_id and str(properties.get("principalId", "")).casefold() not in {
        value.casefold() for value in filters.principal_id
    }:
        return False
    description = properties.get("description") or ""
    if filters.description_contains and not any(
        value.casefold() in description.casefold() for value in filters.description_contains
    ):
        return False
    name = principal.get("displayName") or ""
    if (filters.principal_name or filters.principal_name_contains) and not name:
        raise SafetyError("Cannot evaluate the name filter without a resolved displayName.")
    if filters.principal_name and name.casefold() not in {value.casefold() for value in filters.principal_name}:
        return False
    if filters.principal_name_contains and not any(
        value.casefold() in name.casefold() for value in filters.principal_name_contains
    ):
        return False
    if filters.principal_email:
        if original_type not in ("User", "Group"):
            return False
        if "mail" not in principal or (original_type == "User" and "userPrincipalName" not in principal):
            raise SafetyError("Cannot evaluate the email filter without a resolved mail/UPN response.")
        emails = {str(principal.get(name) or "").casefold() for name in ("mail", "userPrincipalName")}
        if not emails.intersection(value.casefold() for value in filters.principal_email):
            return False
    return True


def build_arg_query(selection, filters):
    query = [
        "AuthorizationResources",
        "| where type =~ 'microsoft.authorization/roleassignments'",
        "| extend assignmentScope = tolower(tostring(properties.scope))",
    ]
    if selection.kind != "management-group":
        literal = json.dumps(selection.root)
        clause = "assignmentScope == " + literal
        if selection.include_children:
            clause += " or assignmentScope startswith " + json.dumps(selection.root + "/")
        query.append("| where " + clause)
    if filters.principal_id:
        query.append("| where tostring(properties.principalId) in~ (" + ", ".join(
            json.dumps(value) for value in filters.principal_id
        ) + ")")
    if filters.principal_type:
        types = {"ServicePrincipal" if value == "ManagedIdentity" else value for value in filters.principal_type}
        query.append("| where tostring(properties.principalType) in~ (" + ", ".join(
            json.dumps(value) for value in sorted(types)
        ) + ")")
    query.extend(["| project id, name, properties", "| order by id asc"])
    return "\n".join(query)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    delete = commands.add_parser("delete", help="Find matching assignments; dry-run unless --apply is given.")
    rollback = commands.add_parser("rollback", help="Restore confirmed deletions from a rollback journal.")
    for command in (delete, rollback):
        mode = command.add_mutually_exclusive_group()
        mode.add_argument("--apply", action="store_true", help="Enable Azure mutations after confirmation.")
        mode.add_argument("--dry-run", action="store_true", help="Preview only (the default).")
        command.add_argument("--yes", action="store_true", help="Skip confirmation, not safety checks.")
        command.add_argument("--tenant-id", type=guid, help="Require this tenant; does not switch accounts.")
        command.add_argument("--rollback-file", required=command is rollback)
        command.add_argument("--allow-ephemeral-backup", action="store_true")
        command.add_argument("--verbose", action="store_true")
        command.add_argument("--timeout", type=int, default=60, help="HTTP/CLI timeout in seconds (default: 60).")
        command.add_argument("--poll-timeout", type=int, default=300, help="PIM completion timeout in seconds.")
    roots = delete.add_mutually_exclusive_group(required=True)
    roots.add_argument("--management-group", type=nonempty, help="Management group ID, not display name.")
    roots.add_argument("--subscription", type=guid)
    roots.add_argument("--resource-id", type=nonempty)
    delete.add_argument("--resource-group", type=nonempty)
    delete.add_argument("--include-resource-descendants", action="store_true")
    for option in ("description-contains", "principal-name", "principal-name-contains", "principal-email"):
        delete.add_argument("--" + option, action="append", type=nonempty, help="Repeat for OR values.")
    delete.add_argument("--principal-id", action="append", type=guid)
    delete.add_argument("--principal-type", action="append", type=principal_type, choices=PRINCIPAL_TYPES)
    delete.add_argument("--assignment-kind", action="append", choices=KINDS, help="Default: regular only.")
    delete.add_argument("--expiration", choices=("any", "permanent", "time-bound"), default="any")
    delete.add_argument("--source", choices=("arg", "arm"), default="arg")
    delete.add_argument("--read-workers", type=int, default=4, help="Concurrent read-only ARM requests (1-16, default: 4).")
    delete.add_argument("--allow-nonrestorable-pim", action="store_true")
    delete.add_argument("--allow-self-removal", action="store_true")
    delete.add_argument("--assume-no-pim", action="store_true",
                        help="Explicitly assert this scope has no PIM; skips PIM verification. Regular RBAC only.")
    rollback.add_argument("--reconcile-pending", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.poll_timeout <= 0:
        parser.error("Timeouts must be positive.")
    if args.command == "delete" and not 1 <= args.read_workers <= 16:
        parser.error("--read-workers must be between 1 and 16.")
    try:
        if args.command == "delete":
            scope_from_args(args)
            reporter = Reporter(args.verbose)
            client = AzureRestClient(args.timeout, args.tenant_id, reporter)
            return execute_delete(client, args, reporter)
        return execute_rollback(args, Reporter(args.verbose))
    except KeyboardInterrupt:
        print("Interrupted. Keep the rollback journal and reconcile any pending intent.", file=sys.stderr)
        return 130
    except (SafetyError, OSError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())