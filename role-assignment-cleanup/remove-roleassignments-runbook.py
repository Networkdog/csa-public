#!/usr/bin/env python3
"""Filter, remove and restore Azure resource RBAC assignments without third-party modules."""

import argparse
import base64
import csv
import hashlib
import http.client
import json
import math
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
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime


RBAC_API = "2022-04-01"
PIM_API = "2020-10-01"
ARG_API = "2024-04-01"
MG_API = "2020-05-01"
SUBSCRIPTION_API = "2022-12-01"
BLOB_API = "2023-11-03"
BLOB_APPEND_BYTES = 4 * 1024 * 1024
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
USER_ACCESS_ADMIN_ROLE_ID = "18d7d88d-d35e-4fb3-a5c3-7773c20a72d9"
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
PIM_ACCESS_EVENTS = {
    "pim_activation_intent", "pim_activation_success", "pim_activation_failure",
    "pim_activation_reused", "pim_cleanup_intent", "pim_cleanup_success", "pim_cleanup_failure",
}
PREVIEW_COLUMNS = ("principal_id", "display_name", "email")
DELETED_USER_COLUMNS = (
    "principal_id", "display_name", "user_principal_name", "email", "deleted_role_assignments",
    "deleted_role_details", "directory_status",
)


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


def parse_time(value, context="timestamp"):
    if value is None:
        return None
    try:
        match = re.fullmatch(
            r"([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt ]((?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])"
            r"(?:\.([0-9]+))?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value if isinstance(value, str) else "",
        )
        if match is None:
            raise ValueError("Expected a timezone-aware ISO timestamp")
        day, clock, fraction, offset = match.groups()
        # Python 3.9/3.10 require 3 or 6 fractional digits; Azure can return other precisions.
        fraction = "." + fraction[:6].ljust(6, "0") if fraction else ""
        offset = "+00:00" if offset.upper() == "Z" else offset
        parsed = datetime.fromisoformat(day + "T" + clock + fraction + offset)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise SafetyError(
            "Invalid timestamp for {} in Azure response or journal. "
            "Expected ISO 8601 YYYY-MM-DDTHH:MM:SS[.fraction] with Z or +/-HH:MM timezone; "
            "received {}. No timestamp value was logged.".format(context, type(value).__name__)
        ) from None


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
    return max(0, delay) if math.isfinite(delay) else 2 ** attempt


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


def role_definition_guid(identifier):
    match = re.fullmatch(
        r"(.*)/providers/microsoft\.authorization/roledefinitions/([0-9a-f-]{36})",
        identifier if isinstance(identifier, str) else "", re.IGNORECASE,
    )
    if not match:
        raise SafetyError("Invalid role definition ARM ID.")
    if match[1]:
        normalize_scope(match[1])
    try:
        return str(uuid.UUID(match[2]))
    except ValueError as error:
        raise SafetyError("Invalid role definition GUID.") from error


def validate_role_definition(raw, identifier):
    if not isinstance(raw, dict) or not isinstance(raw.get("properties"), dict):
        raise SafetyError("Cannot evaluate Custom Role exclusions without a resolved role definition.")
    if role_definition_guid(raw.get("id")) != role_definition_guid(identifier):
        raise SafetyError("ARM returned a different role definition than requested.")
    properties = raw["properties"]
    if (properties.get("type") not in ("CustomRole", "BuiltInRole")
            or not isinstance(properties.get("roleName"), str) or not properties["roleName"].strip()):
        raise SafetyError("Role definition is missing a valid roleName/type; Custom Role exclusion cannot be evaluated.")
    return properties


def resolve_role_definitions(client, properties_list, reporter):
    identifiers = sorted({properties["roleDefinitionId"].casefold() for properties in properties_list})
    definitions = {}
    for index, identifier in enumerate(identifiers, 1):
        raw = get_live_role_definition(client, identifier)
        role = raw["properties"]
        definitions[identifier] = raw
        reporter.detail("Role definition: {} | {} | {}".format(identifier, role["type"], role["roleName"]))
        reporter.progress("Role definitions resolved", index, len(identifiers))
    return definitions


def resolve_assignment_role_details(client, records, reporter):
    missing = [record for record in records if not record.role_name or not record.role_type]
    definitions = resolve_role_definitions(client, [record.properties for record in missing], reporter)
    for record in missing:
        role = definitions[record.properties["roleDefinitionId"].casefold()]["properties"]
        record.role_name = role["roleName"]
        record.role_type = role["type"]


def get_live_role_definition(client, identifier):
    role_definition_guid(identifier)
    raw = client.request("GET", api_path(identifier, RBAC_API))
    validate_role_definition(raw, identifier)
    return raw


def get_subscription_name(client, identifier):
    subscription = client.request("GET", api_path("/subscriptions/" + identifier, SUBSCRIPTION_API))
    if (not isinstance(subscription, dict) or not isinstance(subscription.get("subscriptionId"), str)
            or subscription["subscriptionId"].casefold() != identifier
            or not isinstance(subscription.get("displayName"), str) or not subscription["displayName"].strip()):
        raise SafetyError("Cannot evaluate the subscription display-name filter: " + identifier)
    if subscription.get("tenantId") and (
        not isinstance(subscription["tenantId"], str) or subscription["tenantId"].casefold() != client.tenant
    ):
        raise SafetyError("Subscription tenant does not match the execution tenant: " + identifier)
    return subscription["displayName"]


def verify_subscription_selection(client, selection, scope):
    if not selection.subscription_name_contains:
        return
    if not selection.contains(scope):
        raise SafetyError("Assignment is outside the filtered subscription selection.")
    identifier = normalize_scope(scope).split("/")[2]
    if get_subscription_name(client, identifier) != selection.subscription_names[identifier]:
        raise SafetyError("Subscription display name changed after discovery; no mutation attempted.")


def resolve_scope(client, selection):
    if selection.kind == "management-group":
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
    if selection.subscription_name_contains:
        identifiers = sorted(selection.subscriptions) if selection.kind == "management-group" else [selection.root.split("/")[2]]
        names = {}
        for identifier in identifiers:
            name = get_subscription_name(client, identifier)
            if any(value.casefold() in name.casefold() for value in selection.subscription_name_contains):
                names[identifier] = name
        selection.subscriptions = set(names)
        selection.subscription_names = names
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


def arm_assignments(client, selection, scopes=None, workers=1, reporter=None):
    scopes = sorted(set(selection.read_scopes() if scopes is None else scopes))

    def read_scope(scope):
        records = []
        query = {"$filter": "atScope()"} if scope.startswith("/providers/") else {}
        path = api_path(scope + "/providers/Microsoft.Authorization/roleAssignments", RBAC_API, **query)
        for raw in client.values(path):
            if not selection.contains(raw.get("properties", {}).get("scope")):
                continue
            validate_assignment(raw)
            records.append(raw)
        return records

    results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, records in enumerate(pool.map(read_scope, scopes), 1):
            for raw in records:
                results[raw["id"].casefold()] = raw
            if reporter:
                reporter.progress("ARM bulk scopes", index, len(scopes))
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


def resolve_user_details(client, records, reporter):
    users = [record for record in records if record.properties.get("principalType") == "User"]
    pending = [record.properties for record in users if not record.principal]
    try:
        resolved = resolve_principals(client, pending, reporter) if pending else {}
    except ApiError as error:
        reporter.emit("Graph user lookup failed; no deletion attempted." + (
            " Automation requires Microsoft Graph application User.Read.All with tenant-admin consent."
            if error.status in (401, 403) else " Resolve the Graph HTTP error before applying."))
        raise
    warned = set()
    for record in users:
        identifier = record.properties["principalId"].casefold()
        principal = record.principal or resolved[identifier]
        error = principal.get("resolutionError")
        if error == "Graph HTTP 404":
            principal["directoryStatus"] = "not_found"
            if identifier not in warned:
                reporter.emit("WARNING: User {} was not found in Microsoft Graph; CSV will explicitly mark not_found.".format(identifier))
                warned.add(identifier)
        elif error:
            raise SafetyError(
                "Cannot resolve user {}: {}. {} No deletion attempted.".format(
                    identifier, error,
                    "Automation requires Microsoft Graph application User.Read.All with tenant-admin consent; Azure Owner is not sufficient."
                    if error in ("Graph HTTP 401", "Graph HTTP 403") else "Resolve the directory lookup error before applying.")
            )
        else:
            if (any(principal.get(name) is not None and not isinstance(principal[name], str)
                    for name in ("displayName", "mail", "userPrincipalName"))
                    or not any(str(principal.get(name) or "").strip() for name in ("displayName", "userPrincipalName"))):
                raise SafetyError("Graph returned no usable name/UPN for user {}; refusing a GUID-only success report.".format(identifier))
            principal["directoryStatus"] = "resolved"
        record.principal = principal


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
    role_name: str = ""
    role_type: str = ""

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
        values = [parse_time(item.get("properties", {}).get("endDateTime"),
                             "{} properties.endDateTime".format(item.get("id", self.identifier)))
                  for item in [self.raw, *self.instances]]
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
            record = cls(**{key: value[key] for key in cls.__dataclass_fields__ if key in value})
            validate_assignment(record.raw, collection_for_route(record.route))
            if record.kind not in KINDS:
                raise SafetyError("Unknown assignment kind in journal.")
            if not isinstance(record.role_name, str) or not isinstance(record.role_type, str):
                raise SafetyError("Invalid role-definition metadata in journal.")
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
    start = parse_time(record.properties.get("startDateTime"), record.identifier + " properties.startDateTime") or now
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


def blob_http_error(error, operation, destination):
    headers = error.headers or {}
    code = headers.get("x-ms-error-code")
    request_id = headers.get("x-ms-request-id")
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,127}", code):
        code = None
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", request_id,
    ):
        request_id = "Unavailable"
    read_failed = False
    try:
        if code is None:
            try:
                content = error.read(8192)
            except (OSError, http.client.HTTPException, ValueError):
                read_failed = True
            else:
                if isinstance(content, bytes):
                    match = re.search(rb"<Code>\s*([A-Za-z][A-Za-z0-9]{0,127})\s*</Code>", content)
                    if match:
                        code = match[1].decode("ascii")
                else:
                    read_failed = True
    finally:
        error.close()
    hints = {
        "AuthenticationFailed": "Regenerate an unmodified SAS for this account/container; check signature, expiry and start time.",
        "AuthorizationPermissionMismatch": "Check SAS/stored-policy Write permission for blob creation/append and Read for rollback; a user-delegation SAS also requires its signing identity's Blob data RBAC.",
        "AuthorizationFailure": "Check Storage public-network, firewall, private-endpoint and Automation worker network rules; SAS does not bypass network restrictions.",
        "AuthorizationSourceIPMismatch": "Check SAS signed IP (sip) against the actual Automation/Hybrid worker outbound IP.",
        "KeyBasedAuthenticationNotPermitted": "Shared-key SAS is disabled; use a user-delegation SAS or an administrator-approved storage policy.",
        "AuthorizationServiceMismatch": "An account SAS must authorize the Blob service (ss includes b).",
        "AuthorizationResourceTypeMismatch": "An account SAS must authorize object resource types (srt includes o).",
    }
    hint = hints.get(code, "Check SAS scope/permissions/expiry, network policy and existing-blob conflicts.")
    return JournalError(
        "Blob Storage HTTP {} | code={} | operation={} | request-id={} | target={}. {}{} "
        "No further role mutations allowed; preserve local files for recovery.".format(
            error.code, code or "Unavailable", operation, request_id, destination, hint,
            " Storage error body could not be read." if read_failed else "",
        )
    )


class BlobJournalBackup:
    def __init__(self, sas_url, timeout=60):
        try:
            if not isinstance(sas_url, str) or any(character.isspace() or ord(character) < 32 for character in sas_url):
                raise ValueError("Invalid URL characters")
            parsed = urllib.parse.urlsplit(sas_url)
            if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment
                    or parsed.port not in (None, 443) or not re.fullmatch(
                        r"[a-z0-9]{3,24}\.(?:blob\.core\.(?:windows\.net|usgovcloudapi\.net|chinacloudapi\.cn|cloudapi\.de)"
                        r"|z[0-9]+\.blob\.storage\.azure\.net)", parsed.hostname or "")):
                raise ValueError("Expected an Azure Blob HTTPS endpoint")
            path = urllib.parse.unquote(parsed.path)
            segments = path.split("/")
            if (len(segments) < 3 or not all(segments[1:]) or any(item in (".", "..") for item in segments[1:])
                    or "\\" in path or any(ord(character) < 32 for character in path)):
                raise ValueError("Expected a container and blob path")
            pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            query = dict(pairs)
            if (len(query) != len(pairs) or not query.get("sig") or not query.get("sv")
                    or not (query.get("se") or query.get("si"))
                    or {"comp", "restype", "snapshot", "versionid"}.intersection(key.casefold() for key in query)):
                raise ValueError("Expected a SAS without operation parameters")
            if query.get("sr") not in ("b", "c") and not ("b" in query.get("ss", "") and "o" in query.get("srt", "")):
                raise ValueError("SAS must allow blob objects")
            if (query.get("sp") and not {"r", "w"}.issubset(query["sp"])) or not (query.get("sp") or query.get("si")):
                raise ValueError("SAS must grant read and write permissions")
            if query.get("spr") and "https" not in query["spr"].split(","):
                raise ValueError("SAS must permit HTTPS")
            if query.get("se") and parse_time(query["se"]) <= utc_now():
                raise ValueError("SAS has expired")
            if query.get("st") and parse_time(query["st"]) > utc_now():
                raise ValueError("SAS is not yet valid")
        except (ValueError, SafetyError):
            raise JournalError(
                "Invalid Blob SAS URL. Use an Azure Blob HTTPS URL with a container/blob path, "
                "a valid blob/container/account SAS and read/write permissions. SAS values are never logged."
            ) from None
        self._url = sas_url
        self.destination = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect())
        self.offset = 0
        self.etag = None

    def request(self, method, body=None, headers=None, append=False, read_limit=0, allow_missing=False):
        request_headers = {"x-ms-version": BLOB_API, "x-ms-client-request-id": str(uuid.uuid4()),
                           "Accept-Encoding": "identity"}
        request_headers.update(headers or {})
        url = self._url + "&comp=appendblock" if append else self._url
        try:
            request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.getcode() != (200 if method == "GET" else 201):
                    raise JournalError("Unexpected Blob backup response; local journal retained.")
                return response.headers, response.read(read_limit) if read_limit else b""
        except urllib.error.HTTPError as error:
            if allow_missing and error.code == 404:
                error.close()
                return None
            operation = method + (" append" if append else " read" if method == "GET" else " create")
            raise blob_http_error(error, operation, self.destination) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError, SafetyError):
            raise JournalError(
                "Blob backup failed or its write outcome is uncertain. Local journal retained; "
                "no further mutations allowed. SAS details are suppressed."
            ) from None

    def response_etag(self, headers):
        etag = headers.get("ETag")
        if not isinstance(etag, str) or not etag or any(ord(character) < 32 for character in etag):
            raise JournalError("Blob backup response is missing a valid ETag; no further mutations allowed.")
        return etag

    def initialize(self, stream, create=False, content_type="application/x-ndjson; charset=utf-8"):
        stream.seek(0)
        local = b"" if create else stream.read()
        existing = None if create else self.request("GET", read_limit=len(local) + 1, allow_missing=True)
        if existing is None:
            headers, _ = self.request("PUT", body=b"", headers={
                "If-None-Match": "*", "x-ms-blob-type": "AppendBlob", "Content-Length": "0",
                "x-ms-blob-content-type": content_type,
            })
            self.etag = self.response_etag(headers)
        else:
            headers, remote = existing
            if (headers.get("x-ms-blob-type") != "AppendBlob" or headers.get("Content-Length") != str(len(remote))
                    or not local.startswith(remote)):
                raise JournalError("Existing Blob backup is not an append-only prefix of this local journal; refusing to overwrite.")
            self.etag = self.response_etag(headers)
            self.offset = len(remote)
        self.sync(stream)

    def sync(self, stream):
        stream.seek(0, os.SEEK_END)
        if stream.tell() < self.offset:
            raise JournalError("Local journal is shorter than its Blob backup; refusing to overwrite.")
        stream.seek(self.offset)
        while True:
            payload = stream.read(BLOB_APPEND_BYTES)
            if not payload:
                return
            checksum = base64.b64encode(hashlib.md5(payload, usedforsecurity=False).digest()).decode("ascii")
            headers, _ = self.request("PUT", body=payload, append=True, headers={
                "Content-Length": str(len(payload)), "Content-MD5": checksum, "If-Match": self.etag,
                "x-ms-blob-condition-appendpos": str(self.offset),
            })
            if headers.get("x-ms-blob-append-offset") != str(self.offset) or headers.get("Content-MD5") != checksum:
                raise JournalError("Blob append position/checksum could not be verified; no further mutations allowed.")
            self.etag = self.response_etag(headers)
            self.offset += len(payload)

    def verify(self, stream):
        stream.seek(0, os.SEEK_END)
        expected_size = stream.tell()
        if expected_size != self.offset:
            raise JournalError("Local journal is not fully synchronized to Blob; no role mutations allowed.")
        stream.seek(0)
        expected_hash = hashlib.sha256()
        while True:
            payload = stream.read(BLOB_APPEND_BYTES)
            if not payload:
                break
            expected_hash.update(payload)
        try:
            request = urllib.request.Request(self._url, headers={
                "x-ms-version": BLOB_API, "If-Match": self.etag, "Accept-Encoding": "identity",
            }, method="GET")
            with self.opener.open(request, timeout=self.timeout) as response:
                if (response.getcode() != 200 or self.response_etag(response.headers) != self.etag
                        or response.headers.get("Content-Length") != str(expected_size)
                        or response.headers.get("x-ms-blob-type") != "AppendBlob"):
                    raise JournalError("Rollback Blob readback headers do not match the uploaded journal.")
                actual_hash = hashlib.sha256()
                actual_size = 0
                while True:
                    payload = response.read(BLOB_APPEND_BYTES)
                    if not payload:
                        break
                    actual_size += len(payload)
                    if actual_size > expected_size:
                        raise JournalError("Rollback Blob readback is longer than the local journal.")
                    actual_hash.update(payload)
        except urllib.error.HTTPError as error:
            raise blob_http_error(error, "GET verify", self.destination) from None
        except JournalError:
            raise
        except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError, SafetyError):
            raise JournalError("Rollback Blob readback failed; persistence is not verified. Preserve local files; no further role mutations allowed.") from None
        if actual_size != expected_size or actual_hash.digest() != expected_hash.digest():
            raise JournalError("Rollback Blob SHA256/length does not match the local journal; no further role mutations allowed.")
        return actual_hash.hexdigest()


def blob_backup_from_args(args, reporter):
    if not args.rollback_blob_sas_url_env:
        return None
    sas_url = os.environ.get(args.rollback_blob_sas_url_env)
    if not sas_url:
        raise JournalError("The Blob SAS URL environment variable is missing or empty.")
    backup = BlobJournalBackup(sas_url, args.timeout)
    reporter.emit("Blob backup configured: " + backup.destination)
    if not args.apply:
        reporter.emit("DRY RUN: Blob SAS format checked locally; no Blob requests or uploads.")
    return backup


class RollbackJournal:
    def __init__(self, path, create=False):
        self.path = pathlib.Path(path).expanduser().resolve()
        self.sequence = 0
        self.valid_end = 0
        self.trailing_bytes = 0
        self.append_ready = create
        self.locked = False
        self.blob_backup = None
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
                    self.file.flush()
                    # Byte-range locks use the descriptor offset, not the buffered stream position.
                    os.lseek(self.file.fileno(), 0, os.SEEK_SET)
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        finally:
            self.locked = False
            self.file.close()

    def append(self, event, **data):
        self.append_many([(event, data)])

    def append_many(self, entries):
        if not self.append_ready:
            raise JournalError("Journal append has not been enabled.")
        sequence = self.sequence
        try:
            self.file.seek(0, os.SEEK_END)
            for event, data in entries:
                sequence += 1
                row = dict(data, event=event, seq=sequence, time=iso_time())
                self.file.write((json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
            if sequence == self.sequence:
                return
            self.file.flush()
            os.fsync(self.file.fileno())
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            self.append_ready = False
            raise JournalError("Journal write/fsync failed. Stop all mutations; reconcile the last recorded intent.") from error
        self.sequence = sequence
        if self.blob_backup is not None:
            try:
                self.blob_backup.sync(self.file)
            except (JournalError, OSError) as error:
                self.append_ready = False
                if isinstance(error, JournalError):
                    raise
                raise JournalError("Cannot read the local journal for Blob backup; no further mutations allowed.") from error

    def enable_blob_backup(self, backup, create=False, verify=False):
        try:
            backup.initialize(self.file, create=create)
            if verify:
                backup.verify(self.file)
        except (JournalError, OSError) as error:
            self.append_ready = False
            if isinstance(error, JournalError):
                raise
            raise JournalError("Cannot read the local journal for Blob backup; no further mutations allowed.") from error
        self.blob_backup = backup

    def verify_blob_backup(self):
        if self.blob_backup is None:
            raise JournalError("A required rollback Blob was not configured.")
        try:
            return self.blob_backup.verify(self.file)
        except (JournalError, OSError):
            self.append_ready = False
            raise

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
                if not rows and line.decode("utf-8-sig").rstrip("\r\n") == ",".join(PREVIEW_COLUMNS):
                    raise JournalError("CSV preview cannot be used for rollback; use the JSONL journal created by --apply.")
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
    preview = args.command == "delete" and not args.apply
    if args.command == "delete" and args.preview_file and not preview:
        raise SafetyError("--preview-file is only available for delete dry-run.")
    if preview and args.preview_file and args.rollback_file:
        raise SafetyError("Use --preview-file for CSV, not both --preview-file and --rollback-file.")
    drive = pathlib.Path.home() / "clouddrive"
    mounted_drive = drive.exists() and os.path.ismount(drive.resolve())
    specified = args.preview_file if preview and args.preview_file else args.rollback_file
    if specified:
        path = pathlib.Path(specified).expanduser().resolve()
        if preview and args.preview_file and path.suffix.casefold() != ".csv":
            raise SafetyError("--preview-file must name a .csv file.")
        if preview and not args.preview_file:
            path = path.with_suffix(".csv")
            print("WARNING: Dry run now exports CSV. Use --preview-file; CSV output: " + str(path), file=sys.stderr)
    else:
        base = drive if mounted_drive else pathlib.Path.cwd()
        label = "apply" if args.apply else "preview"
        extension = ".csv" if preview else ".jsonl"
        path = base / ("role-assignment-{}-{}-{}{}".format(label, utc_now().strftime("%Y%m%dT%H%M%SZ"),
                                                         uuid.uuid4().hex[:8], extension))
    cloud_shell = any(name.startswith("ACC_") for name in os.environ) or bool(os.environ.get("CLOUD_SHELL"))
    persistent = mounted_drive and (path == drive.resolve() or drive.resolve() in path.parents)
    if cloud_shell and not persistent:
        if args.apply and not (args.allow_ephemeral_backup and args.rollback_file):
            raise JournalError("Use mounted ~/clouddrive for rollback, or explicitly set --rollback-file and --allow-ephemeral-backup.")
        print("WARNING: This Cloud Shell {} may be lost when the session ends.".format(
            "CSV preview" if preview else "journal"), file=sys.stderr)
    if preview and path.exists():
        raise SafetyError("CSV preview already exists; choose a new --preview-file: " + str(path))
    return path


def csv_text(value):
    text = str(value or "")
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def write_csv_report(path, columns, rows):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({name: csv_text(value) for name, value in row.items()})
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, UnicodeError, csv.Error) as error:
        raise SafetyError("Cannot write the CSV report; the file may be incomplete: " + str(path)) from error


def write_preview_csv(path, records, reporter):
    principals = {}
    for record in records:
        identifier = record.properties["principalId"].casefold()
        principal = record.principal
        if not isinstance(principal, dict):
            raise ValueError("Invalid principal metadata")
        row = principals.setdefault(identifier, dict.fromkeys(PREVIEW_COLUMNS, ""))
        row["principal_id"] = identifier
        row["display_name"] = row["display_name"] or principal.get("displayName") or (
            "[Directory object not found]" if principal.get("directoryStatus") == "not_found" else "")
        row["email"] = row["email"] or principal.get("mail") or principal.get("userPrincipalName") or ""
        if principal.get("resolutionError"):
            reporter.detail("Principal metadata unavailable: {} | {}".format(identifier, principal["resolutionError"]))
    write_csv_report(path, PREVIEW_COLUMNS, (principals[key] for key in sorted(principals)))
    reporter.emit("CSV preview: {} | Unique matching principals: {}.".format(path, len(principals)))


def write_deleted_users_csv(journal_path, path):
    snapshots, role_details, users, intents, successful = {}, {}, {}, set(), set()
    complete = False
    try:
        with journal_path.open("rb") as stream:
            for sequence, line in enumerate(stream, 1):
                if not line.endswith(b"\n"):
                    raise ValueError("Incomplete journal record")
                row = json.loads(line)
                if not isinstance(row, dict) or row.get("seq") != sequence:
                    raise ValueError("Invalid journal sequence")
                event, key = row.get("event"), row.get("key")
                if sequence == 1 and (event != "header" or row.get("mode") != "apply" or row.get("schemaVersion") != 1):
                    raise ValueError("Not an apply journal")
                if event == "snapshot":
                    record = AssignmentRecord.from_snapshot(row.get("record", {}))
                    if complete or key != record.key or key in snapshots:
                        raise ValueError("Invalid snapshot")
                    principal = record.principal
                    snapshots[key] = None if record.properties.get("principalType") != "User" else {
                        "principal_id": record.properties["principalId"].casefold(),
                        "display_name": principal.get("displayName") or "",
                        "user_principal_name": principal.get("userPrincipalName") or "",
                        "email": principal.get("mail") or principal.get("userPrincipalName") or "",
                        "directory_status": principal.get("directoryStatus", "not_requested"),
                        "deleted_role_assignments": 0,
                        "deleted_role_details": [],
                    }
                    role_details[key] = None if snapshots[key] is None else {
                        "role_name": record.role_name,
                        "role_type": record.role_type,
                        "role_definition_id": record.properties["roleDefinitionId"],
                        "scope": record.properties["scope"],
                        "kind": record.kind,
                        "assignment_id": record.identifier,
                    }
                elif event == "plan_complete":
                    if complete or row.get("count") != len(snapshots):
                        raise ValueError("Invalid backup plan")
                    complete = True
                elif event == "delete_intent":
                    if not complete or key not in snapshots or key in intents:
                        raise ValueError("Invalid deletion intent")
                    intents.add(key)
                elif event == "delete_success":
                    if key not in intents or key in successful:
                        raise ValueError("Invalid successful deletion")
                    successful.add(key)
                    user = snapshots[key]
                    if user is not None:
                        saved = users.setdefault(user["principal_id"], user)
                        saved["deleted_role_assignments"] += 1
                        role = role_details[key]
                        role_name = role["role_name"] or "[Role name not recorded]"
                        role_type = role["role_type"] or "unknown"
                        saved["deleted_role_details"].append(
                            "Role: {} | Type: {} | Role definition ID: {} | Scope: {} | Kind: {} | Assignment ID: {}".format(
                                role_name, role_type, role["role_definition_id"], role["scope"],
                                role["kind"], role["assignment_id"],
                            )
                        )
        if not complete:
            raise ValueError("No complete backup plan")
    except (OSError, ValueError, UnicodeError, SafetyError) as error:
        raise SafetyError("Cannot build deleted-user CSV from an incomplete/invalid apply journal: " + str(journal_path)) from error
    rows = []
    for key in sorted(users):
        user = dict(users[key])
        user["deleted_role_details"] = "\n".join(user["deleted_role_details"])
        rows.append(user)
    write_csv_report(path, DELETED_USER_COLUMNS, rows)
    return len(users), sum(row["deleted_role_assignments"] for row in users.values())


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
    end = parse_time(properties.get("endDateTime"), raw["id"] + " properties.endDateTime")
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
        return self.selection.read_scopes()

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


def collect_rbac_assignments(client, selection, filters, source, reporter, workers=4):
    if source == "arm":
        records = arm_assignments(client, selection, workers=workers, reporter=reporter)
        reporter.emit("RBAC inventory: {} assignments from authoritative ARM lists; no initial per-ID GET.".format(len(records)))
        return {raw["id"].casefold(): raw for raw in records}
    if source != "arg":
        raise SafetyError("Unsupported RBAC inventory source: " + str(source))
    candidates = arg_assignments(client, selection, filters, reporter)
    identifiers = {raw["id"].casefold(): raw["id"] for raw in candidates
                   if selection.contains(entity_scope(raw["id"], "roleAssignments"))}
    if not identifiers:
        reporter.emit("ARG candidates: 0; no ARM role-assignment lists required.")
        return {}
    scopes = set()
    for identifier in identifiers.values():
        if selection.kind != "management-group":
            scopes.add(selection.root)
        else:
            scope = entity_scope(identifier, "roleAssignments")
            scopes.add("/subscriptions/" + scope.split("/")[2] if scope.startswith("/subscriptions/") else scope)
    reporter.emit("ARG candidates: {}. Reading authoritative ARM lists in {} scope(s).".format(len(identifiers), len(scopes)))
    records = arm_assignments(client, selection, scopes=scopes, workers=workers, reporter=reporter)
    backing = {raw["id"].casefold(): raw for raw in records if raw["id"].casefold() in identifiers}
    bulk_count = len(backing)
    missing = [identifiers[key] for key in sorted(set(identifiers) - set(backing))]
    if missing:
        reporter.emit("ARM lists omitted {} ARG candidate(s); verifying only these IDs with GET.".format(len(missing)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for index, raw in enumerate(pool.map(lambda identifier: get_live_assignment(client, identifier), missing), 1):
                if raw is not None:
                    backing[raw["id"].casefold()] = raw
                reporter.progress("ARM fallback reads", index, len(missing))
    reporter.emit("RBAC inventory: bulk={}, GET fallback={}, absent={}.".format(
        bulk_count, len(missing), len(identifiers) - len(backing)))
    return backing


def discover_records(client, selection, filters, source, reporter, workers=4, assume_no_pim=False):
    if assume_no_pim and set(filters.assignment_kind) != {"regular"}:
        raise SafetyError("--assume-no-pim is only allowed with --assignment-kind regular.")
    resolve_scope(client, selection)
    if selection.subscription_name_contains:
        reporter.emit("Subscriptions matching display-name filter: {}.".format(len(selection.subscriptions)))
        for identifier, name in sorted(selection.subscription_names.items()):
            reporter.emit("Subscription: {} | {}".format(name, identifier))
    if (selection.subscription_name_contains or selection.subscriptions_only) and not selection.subscriptions:
        reporter.emit("No subscriptions inside the selected scope; Azure mutations=0.")
        return [], PimInventory(client, selection, reporter, "pim-eligible" in filters.assignment_kind, assume_no_pim)
    backing = collect_rbac_assignments(client, selection, filters, source, reporter, workers)
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
    property_filters = replace(filters, exclude_custom_role_name_prefix=())
    matched = [record for record in filtered if matches_filters(
        record.properties, property_filters, record.kind, record.principal, record.end,
    )]
    if filters.exclude_custom_role_name_prefix:
        definitions = resolve_role_definitions(client, [record.properties for record in matched], reporter)
        retained = []
        for record in matched:
            definition = definitions[record.properties["roleDefinitionId"].casefold()]
            if matches_filters(record.properties, filters, record.kind, record.principal, record.end, definition):
                record.role_name = definition["properties"]["roleName"]
                record.role_type = definition["properties"]["type"]
                retained.append(record)
        matched = retained
    reporter.emit("Matched: {}. Excluded by kind/filters: {}.".format(len(matched), len(records) - len(matched)))
    return matched, inventory


def scope_document(selection):
    return {
        "kind": selection.kind, "root": selection.root, "include_children": selection.include_children,
        "management_groups": sorted(selection.management_groups), "subscriptions": sorted(selection.subscriptions),
        "subscription_name_contains": list(selection.subscription_name_contains),
        "subscription_names": dict(selection.subscription_names),
        "subscriptions_only": selection.subscriptions_only,
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
        subscriptions_only = value.get("subscriptions_only", False)
        if not isinstance(subscriptions_only, bool) or (subscriptions_only and kind != "management-group"):
            raise ValueError("Invalid subscriptions-only scope setting")
        keywords = value.get("subscription_name_contains", [])
        names = value.get("subscription_names", {})
        if (not isinstance(keywords, list) or any(not isinstance(item, str) or not item.strip() for item in keywords)
                or not isinstance(names, dict) or any(not isinstance(name, str) or not name.strip() for name in names.values())):
            raise ValueError("Invalid subscription display-name filter")
        subscriptions = {guid(item) for item in value["subscriptions"]}
        names = {guid(item): name for item, name in names.items()}
        if keywords and (set(names) != subscriptions or any(
            not any(keyword.casefold() in name.casefold() for keyword in keywords) for name in names.values()
        )):
            raise ValueError("Subscription names do not match the recorded selection")
        return ScopeSelection(kind, root, value["include_children"],
                              {normalize_scope(item) for item in value["management_groups"]},
                              subscriptions, tuple(keywords), names, subscriptions_only)
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
        expired = parse_time(properties.get("endDateTime"), current["id"] + " properties.endDateTime")
        if properties.get("status") not in ("Revoked", "Canceled") and not (expired and expired <= utc_now()):
            return False
    origins = {record.rbac["id"]} if record.rbac else set()
    if record.route == "assignment":
        origins.update(reference_id(record.scope, instance["properties"]["originRoleAssignmentId"], "roleAssignments")
                       for instance in record.instances if instance["properties"].get("originRoleAssignmentId"))
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
    verify_subscription_selection(client, inventory.selection, record.scope)
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
    definition = None
    if filters and filters.exclude_custom_role_name_prefix:
        definition = get_live_role_definition(client, current.properties["roleDefinitionId"])
    if filters and not matches_filters(current.properties, filters, current.kind, current.principal, current.end, definition):
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


class TemporaryPimAccess:
    def __init__(self, eligibility, activation=None):
        self.eligibility = eligibility
        self.activation = activation
        self.reused = activation is not None
        self.request_id = str(uuid.uuid4())
        self.attempted = False
        self.rejected = False
        self.deactivate_after = 0

    def endpoint(self, request_id=None):
        return api_path(self.eligibility.scope + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/"
                        + (request_id or self.request_id), PIM_API)

    def target(self, response):
        properties = response.get("properties", {}) if isinstance(response, dict) else {}
        if properties.get("requestType") != "SelfActivate" or not same_assignment(self.eligibility.raw, response):
            raise SafetyError("Temporary PIM request identity does not match the confirmed eligibility.")
        return reference_id(self.eligibility.scope, properties.get("targetRoleAssignmentScheduleId"), "roleAssignmentSchedules")

    def wait_activation(self, client, target, timeout, reporter, require_backing=True):
        deadline = time.monotonic() + timeout
        inventory = PimInventory(client, ScopeSelection("subscription", self.eligibility.scope), reporter)
        while True:
            inventory.load(self.eligibility.scope, exact=True)
            schedule = inventory.schedules.get(target.casefold())
            if schedule and pim_kind(schedule, "assignment") is not None:
                linked = reference_id(self.eligibility.scope, schedule["properties"].get("linkedRoleEligibilityScheduleId"),
                                      "roleEligibilitySchedules")
                if (pim_kind(schedule, "assignment") != "pim-activated"
                        or not same_assignment(self.eligibility.raw, schedule)
                        or linked != self.eligibility.identifier.casefold()):
                    raise SafetyError("Temporary PIM activation does not match the confirmed eligibility.")
                instances = inventory.instances_for(schedule)
                if len(instances) > 1:
                    raise SafetyError("Temporary PIM activation has multiple instances.")
                if instances or not require_backing:
                    backing = None
                    if require_backing:
                        origin = reference_id(self.eligibility.scope, instances[0]["properties"].get("originRoleAssignmentId"),
                                              "roleAssignments")
                        backing = get_live_assignment(client, origin)
                    if backing or not require_backing:
                        activation = (inventory.from_schedule(schedule, "assignment", backing) if instances
                                      else AssignmentRecord(schedule, route="assignment", kind="pim-activated"))
                        if activation is not None:
                            self.activation = activation
                            self.deactivate_after = time.monotonic() + 300
                            return
            if time.monotonic() >= deadline:
                raise SafetyError("Temporary PIM activation is not observable in both PIM and live RBAC.")
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def activate(self, client, journal, timeout, reporter):
        current = client.get_optional(api_path(self.eligibility.identifier, PIM_API))
        if current is None:
            raise SafetyError("PIM eligibility disappeared after discovery; no activation attempted.")
        validate_assignment(current, "roleEligibilitySchedules")
        if AssignmentRecord(current, route="eligibility", kind="pim-eligible").fingerprint() != self.eligibility.fingerprint():
            raise SafetyError("PIM eligibility changed after discovery; no activation attempted.")
        if self.reused:
            self.wait_activation(client, self.activation.identifier, timeout, reporter)
            journal.append("pim_activation_reused", scope=self.eligibility.scope, activationId=self.activation.identifier)
            reporter.emit("Using existing PIM activation (will not deactivate it): " + self.eligibility.scope)
            return
        now = utc_now()
        end = min(now + timedelta(hours=1), self.eligibility.end) if self.eligibility.end else now + timedelta(hours=1)
        end = end.replace(microsecond=0)
        if (end - now).total_seconds() < 300:
            raise SafetyError("PIM eligibility has less than five minutes remaining.")
        properties = {
            "principalId": self.eligibility.properties["principalId"],
            "roleDefinitionId": self.eligibility.properties["roleDefinitionId"],
            "requestType": "SelfActivate", "linkedRoleEligibilityScheduleId": self.eligibility.identifier.rsplit("/", 1)[1],
            "justification": "Temporarily activate existing eligibility for Owner removal by remove-roleassignments.py",
            "scheduleInfo": {"startDateTime": iso_time(now), "expiration": {"type": "AfterDateTime", "endDateTime": iso_time(end)}},
        }
        journal.append("pim_activation_intent", activationRequestId=self.request_id, scope=self.eligibility.scope,
                       eligibilityId=self.eligibility.identifier, principalId=properties["principalId"],
                       roleDefinitionId=properties["roleDefinitionId"], expiresAt=iso_time(end))
        self.attempted = True
        reporter.emit("Activating temporary PIM access: " + self.eligibility.scope)
        try:
            client.request("PUT", self.endpoint(), {"properties": properties})
        except ApiError as error:
            self.rejected = error.status in (400, 401, 403, 404, 409, 422, 429)
            raise
        response = wait_pim_request(client, self.endpoint(), timeout, reporter)
        self.wait_activation(client, self.target(response), timeout, reporter)
        if self.activation.end is None or self.activation.end > end:
            raise SafetyError("Temporary PIM activation did not preserve the requested bounded expiration.")
        journal.append("pim_activation_success", activationRequestId=self.request_id, activation=self.activation.snapshot())
        client.access_token("arm", refresh=True)

    def cleanup(self, client, journal, timeout, reporter):
        if not self.attempted:
            return
        if self.rejected:
            journal.append("pim_cleanup_success", activationRequestId=self.request_id, status="activation_rejected")
            return
        response = client.get_optional(self.endpoint())
        if response is None:
            raise SafetyError("Temporary PIM activation request is not observable; inspect request " + self.request_id)
        status = response.get("properties", {}).get("status")
        if status not in PIM_TERMINAL and status not in ("Provisioned", "Granted", "ScheduleCreated"):
            journal.append("pim_cleanup_intent", activationRequestId=self.request_id, operation="cancel")
            cancel_path = api_path(self.eligibility.scope + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/"
                                   + self.request_id + "/cancel", PIM_API)
            try:
                client.request("POST", cancel_path)
            except ApiError as error:
                if error.status != 409:
                    raise
                reporter.emit("PIM cancellation raced with provisioning; checking this request before cleanup.")
            response = client.request("GET", self.endpoint())
            status = response.get("properties", {}).get("status")
        if status in PIM_TERMINAL:
            probe = self.activation
            if probe is None and response.get("properties", {}).get("targetRoleAssignmentScheduleId"):
                probe = AssignmentRecord({"id": self.target(response), "properties": dict(self.eligibility.properties)},
                                         route="assignment", kind="pim-activated")
            if probe is None or removal_observed(client, probe):
                journal.append("pim_cleanup_success", activationRequestId=self.request_id, status=status)
                return
            reporter.emit("PIM request is terminal but its activation remains; cleaning up the observed activation.")
        elif status not in ("Provisioned", "Granted", "ScheduleCreated"):
            raise SafetyError("Temporary PIM request is still pending; cancel it in PIM: " + self.request_id)
        if self.activation is None:
            self.wait_activation(client, self.target(response), timeout, reporter, require_backing=False)
        if not removal_observed(client, self.activation):
            delay = max(0, self.deactivate_after - time.monotonic())
            if delay:
                reporter.emit("Waiting up to {:.0f}s for Azure PIM's five-minute minimum before deactivation.".format(delay))
                time.sleep(delay)
            if not removal_observed(client, self.activation):
                request_id = str(uuid.uuid4())
                journal.append("pim_cleanup_intent", activationRequestId=self.request_id, operation="SelfDeactivate",
                               requestId=request_id, activationId=self.activation.identifier)
                properties = {
                    "principalId": self.activation.properties["principalId"],
                    "roleDefinitionId": self.activation.properties["roleDefinitionId"],
                    "requestType": "SelfDeactivate", "targetRoleAssignmentScheduleId": self.activation.identifier.rsplit("/", 1)[1],
                    "justification": "End temporary Owner-removal access created by remove-roleassignments.py",
                }
                endpoint = self.endpoint(request_id)
                client.request("PUT", endpoint, {"properties": properties})
                wait_pim_request(client, endpoint, timeout, reporter)
                wait_removed(client, self.activation, timeout)
        journal.append("pim_cleanup_success", activationRequestId=self.request_id, status="deactivated_or_expired")
        client.access_token("arm", refresh=True)
        reporter.emit("Temporary PIM access removed: " + self.eligibility.scope)


def plan_pim_owner_access(client, inventory, actionable, reporter):
    scopes = sorted({record.scope for record in actionable
                     if record.scope.startswith("/subscriptions/") and len(record.scope.split("/")) == 3
                     and record.properties["roleDefinitionId"].rsplit("/", 1)[-1].casefold() == OWNER_ROLE_ID})
    if not scopes:
        reporter.emit("PIM Owner-removal helper: no removable subscription-level Owner assignments.")
        return []
    if not client.actor_id:
        raise SafetyError("Caller Object ID is required to activate existing PIM eligibility.")
    actor = client.actor_id.casefold()
    targeted = {(record.scope, record.properties["principalId"].casefold(),
                 record.properties["roleDefinitionId"].rsplit("/", 1)[-1].casefold()) for record in actionable}
    inventory.include_eligible = True
    plans = []
    for scope in scopes:
        inventory.load(scope, exact=True)
        candidates = []
        for raw in inventory.eligibilities.values():
            properties = raw["properties"]
            role = properties["roleDefinitionId"].rsplit("/", 1)[-1].casefold()
            if (normalize_scope(properties["scope"]) != scope or properties["principalId"].casefold() != actor
                    or properties.get("principalType") != "User" or role not in (OWNER_ROLE_ID, USER_ACCESS_ADMIN_ROLE_ID)
                    or properties.get("condition") or (scope, actor, role) in targeted):
                continue
            if pim_kind(raw, "eligibility") is None:
                continue
            start = parse_time(properties.get("startDateTime"), raw["id"] + " properties.startDateTime")
            end = parse_time(properties.get("endDateTime"), raw["id"] + " properties.endDateTime")
            if (start and start > utc_now()) or (end and (end - utc_now()).total_seconds() < 300):
                continue
            eligibility = inventory.from_schedule(raw, "eligibility")
            if eligibility is None:
                continue
            activations = [schedule for schedule in inventory.schedules.values()
                           if same_assignment(raw, schedule) and pim_kind(schedule, "assignment") == "pim-activated"]
            if len(activations) > 1:
                raise SafetyError("Multiple PIM activations match a temporary-access candidate.")
            activation = inventory.from_schedule(activations[0], "assignment") if activations else None
            candidates.append((activation is None, role != USER_ACCESS_ADMIN_ROLE_ID, eligibility.identifier,
                               TemporaryPimAccess(eligibility, activation)))
        if not candidates:
            raise SafetyError("No usable direct, unconditional caller Eligible Owner/User Access Administrator at " + scope
                              + ". The source eligibility/role must not be in the deletion set; new eligibility is never created.")
        plan = min(candidates, key=lambda item: item[:3])[3]
        plans.append(plan)
        reporter.emit("PIM Owner-removal plan: {} | {} | {}".format(
            scope, plan.eligibility.identifier,
            "reuse existing activation" if plan.reused else "activate for at most one hour, then deactivate"))
    return plans


def pending_pim_access(rows):
    pending = {}
    for row in rows:
        request_id = row.get("activationRequestId")
        if row.get("event") == "pim_activation_intent":
            pending[request_id] = dict(row)
        elif row.get("event") == "pim_activation_success" and request_id in pending:
            pending[request_id]["activation"] = row.get("activation")
        elif row.get("event") == "pim_cleanup_success":
            pending.pop(request_id, None)
    return list(pending.values())


def check_pim_cleanup(client, pending, selection, reporter):
    unresolved = 0
    for access in pending:
        try:
            scope = normalize_scope(access.get("scope"))
            if not scope.startswith("/subscriptions/") or len(scope.split("/")) != 3 or not selection.contains(scope):
                raise SafetyError("Temporary PIM scope is outside the original subscription selection.")
            expected = {"id": access.get("eligibilityId"), "properties": {
                "scope": scope, "principalId": access.get("principalId"), "roleDefinitionId": access.get("roleDefinitionId"),
            }}
            validate_assignment(expected, "roleEligibilitySchedules")
            if access.get("activation"):
                record = AssignmentRecord.from_snapshot(access["activation"])
                if record.route != "assignment" or record.kind != "pim-activated" or not same_assignment(expected, record.raw):
                    raise SafetyError("Temporary PIM snapshot does not match its activation intent.")
            else:
                endpoint = api_path(reference_id(scope, access.get("activationRequestId"), "roleAssignmentScheduleRequests"), PIM_API)
                response = client.get_optional(endpoint)
                if (not isinstance(response, dict) or not isinstance(response.get("properties"), dict)
                        or response["properties"].get("requestType") != "SelfActivate" or not same_assignment(expected, response)):
                    raise SafetyError("Temporary PIM request outcome is not observable.")
                properties = response["properties"]
                if properties.get("status") not in PIM_TERMINAL | {"Provisioned", "Granted", "ScheduleCreated"}:
                    raise SafetyError("Temporary PIM activation request is still pending; cancel it in PIM.")
                target = properties.get("targetRoleAssignmentScheduleId")
                if not target:
                    if properties.get("status") not in PIM_TERMINAL:
                        raise SafetyError("Temporary PIM request has no observable target.")
                    reporter.emit("Temporary PIM request is terminal: " + str(access.get("activationRequestId")))
                    continue
                target = reference_id(scope, target, "roleAssignmentSchedules")
                current = client.get_optional(api_path(target, PIM_API))
                if current is None and properties.get("status") not in PIM_TERMINAL:
                    raise SafetyError("Temporary PIM target is not observable; its creation outcome is uncertain.")
                record = AssignmentRecord({"id": target, "properties": expected["properties"]},
                                          route="assignment", kind="pim-activated")
            if not removal_observed(client, record):
                raise SafetyError("Temporary PIM activation or backing RBAC assignment is still present.")
            reporter.emit("Temporary PIM cleanup verified: " + str(access.get("activationRequestId")))
        except (SafetyError, OSError) as error:
            unresolved += 1
            reporter.emit("MANUAL PIM CHECK REQUIRED: {} | request {} | expiry {} | {}".format(
                access.get("scope"), access.get("activationRequestId"), access.get("expiresAt"), error))
    return unresolved


@dataclass(frozen=True)
class DeleteOutcome:
    key: str
    status: str
    event: str
    detail: str = ""

    def journal_entry(self):
        data = {"key": self.key}
        if self.detail:
            data["error" if self.event in ("delete_failure", "delete_uncertain") else "reason"] = self.detail
        return self.event, data


def subscription_work_key(record):
    return record.scope.split("/")[2] if record.scope.startswith("/subscriptions/") else record.scope


def deletion_batches(records, size):
    stages = {}
    for record in records:
        stage = (record.route == "eligibility", -record.scope.count("/"), record.route == "rbac")
        queues = stages.setdefault(stage, {})
        queues.setdefault(subscription_work_key(record), deque()).append(record)
    for stage in sorted(stages):
        queues = stages[stage]
        batch = []
        while queues:
            for key in sorted(queues):
                batch.append(queues[key].popleft())
                if not queues[key]:
                    del queues[key]
                if len(batch) == size:
                    yield batch
                    batch = []
        if batch:
            yield batch


def delete_with_intent(client, record, inventory, filters, args, reporter, request_id, stop):
    if stop.is_set():
        return DeleteOutcome(record.key, "unprocessed", "delete_skipped", "Canceled after another failure; no mutation attempted.")
    attempted = False
    try:
        current = refresh_record(client, record, inventory, filters)
        if current is None:
            return DeleteOutcome(record.key, "skipped", "delete_skipped", "Already missing/expired before mutation.")
        if record.route == "eligibility" and fresh_linked_activations(client, record, reporter):
            raise SafetyError("A linked activation is still present; no eligibility removal attempted.")
        if stop.is_set():
            return DeleteOutcome(record.key, "unprocessed", "delete_skipped", "Canceled after another failure; no mutation attempted.")
        attempted = True
        if record.route == "rbac":
            client.request("DELETE", api_path(record.identifier, RBAC_API))
        else:
            endpoint = request_path(record, request_id)
            client.request("PUT", endpoint, pim_remove_body(record))
            wait_pim_request(client, endpoint, args.poll_timeout, reporter)
        wait_removed(client, record, args.poll_timeout)
        return DeleteOutcome(record.key, "deleted", "delete_success")
    except JournalError:
        stop.set()
        raise
    except (SafetyError, OSError) as error:
        stop.set()
        rejected = isinstance(error, ApiError) and error.status in (400, 401, 403, 404, 409, 422, 429)
        return DeleteOutcome(record.key, "failed", "delete_uncertain" if attempted and not rejected else "delete_failure", str(error))


def execute_batched_deletes(client, records, inventory, filters, args, reporter, journal):
    stop = threading.Event()
    limits = {key: threading.Semaphore(4) for key in {subscription_work_key(record) for record in records}}
    counts = {"deleted": 0, "skipped": 0, "failed": 0}
    reported_failure = False
    checked = 0

    def remove_regular(record, request_id):
        with limits[subscription_work_key(record)]:
            local = PimInventory(client, inventory.selection, reporter, assume_no_pim=inventory.assume_no_pim)
            return delete_with_intent(client, record, local, filters, args, reporter, request_id, stop)

    with ThreadPoolExecutor(max_workers=args.delete_workers) as pool:
        for batch in deletion_batches(records, args.delete_batch_size):
            if stop.is_set():
                break
            requests = [(record, str(uuid.uuid4()) if record.route != "rbac" else None) for record in batch]
            journal.append_many(("delete_intent", {"key": record.key, "requestId": request_id})
                                for record, request_id in requests)
            if batch[0].route == "rbac":
                complete = False
                try:
                    futures = [pool.submit(remove_regular, record, request_id) for record, request_id in requests]
                    outcomes = [future.result() for future in as_completed(futures)]
                    complete = True
                finally:
                    if not complete:
                        stop.set()
            else:
                outcomes = [delete_with_intent(client, record, inventory, filters, args, reporter, request_id, stop)
                            for record, request_id in requests]
            journal.append_many(outcome.journal_entry() for outcome in outcomes)
            for outcome in outcomes:
                if outcome.status in counts:
                    counts[outcome.status] += 1
                if outcome.status == "failed" and not reported_failure:
                    reporter.emit("STOP: {}. In-flight operations finished; no further batch will start.".format(outcome.detail))
                    reported_failure = True
            checked += len(outcomes)
            reporter.progress("Delete outcomes", checked, len(records))
    return counts["deleted"], counts["skipped"], counts["failed"]


def execute_delete(client, args, reporter):
    args.rollback_blob_verified = False
    args.rollback_blob_initial_verified = False
    if not 1 <= args.delete_workers <= 32 or not 1 <= args.delete_batch_size <= 500:
        raise SafetyError("--delete-workers must be 1-32 and --delete-batch-size must be 1-500.")
    if args.use_pim_for_owner_removal and args.assume_no_pim:
        raise SafetyError("--use-pim-for-owner-removal cannot be combined with --assume-no-pim.")
    selection = scope_from_args(args)
    filters = FilterSpec.from_args(args)
    path = journal_path(args)
    blob_backup = blob_backup_from_args(args, reporter)
    if args.apply and args.require_blob_backup and blob_backup is None:
        raise JournalError("Blob rollback backup is mandatory; configure --rollback-blob-sas-url-env before applying.")
    reporter.emit("Tenant: {} | Cloud: {} | Mode: {}".format(client.tenant, client.cloud, "APPLY" if args.apply else "DRY RUN"))
    reporter.emit("Scope: " + selection.root)
    records, inventory = discover_records(client, selection, filters, args.source, reporter, args.read_workers, args.assume_no_pim)
    if args.include_user_details:
        resolve_user_details(client, records, reporter)
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
    if args.apply and args.include_user_details:
        users = [record for record in actionable if record.properties.get("principalType") == "User"]
        resolve_assignment_role_details(client, users, reporter)
    pim_access = plan_pim_owner_access(client, inventory, actionable, reporter) if args.use_pim_for_owner_removal else []
    reporter.emit("Removable: {} | Protected: {}".format(len(actionable), len(blocked)))
    for index, record in enumerate(records):
        if reporter.verbose or index < 10:
            reporter.emit(describe_record(record) + (" | PROTECTED: " + blocked[record.key] if record.key in blocked else ""))
    if len(records) > 10 and not reporter.verbose:
        reporter.emit("First 10 shown; {}.".format(
            "the complete matching list is in the rollback journal" if args.apply
            else "the CSV contains unique matching principals; use --verbose for all assignment details"))
    if not args.apply:
        write_preview_csv(path, records, reporter)
        reporter.emit("DRY RUN: matched={}, removable={}, protected={}, Azure mutations=0.".format(
            len(records), len(actionable), len(blocked)))
        return 0
    deleted, skipped, failed, pim_failed = 0, 0, 0, 0
    with RollbackJournal(path, create=True) as journal:
        journal.append("header", schemaVersion=1, runId=str(uuid.uuid4()), mode="apply" if args.apply else "dry-run",
                       tenantId=client.tenant, cloud=client.cloud, callerId=client.actor_id,
                       selection=scope_document(selection), filters=asdict(filters), source=args.source,
                       pimCheck="operator-asserted-absent" if args.assume_no_pim else "verified",
                       pimOwnerRemoval=args.use_pim_for_owner_removal,
                       blobBackupEnabled=blob_backup is not None,
                       temporaryPimAccess=[{"scope": access.eligibility.scope, "eligibilityId": access.eligibility.identifier,
                                            "roleDefinitionId": access.eligibility.properties["roleDefinitionId"],
                                            "reuse": access.reused} for access in pim_access])
        journal.append_many(("snapshot", {"key": record.key, "record": record.snapshot(), "blockedReason": blocked.get(record.key)})
                            for record in records)
        journal.append("plan_complete", count=len(records), actionable=len(actionable))
        reporter.emit("Rollback journal: " + str(journal.path))
        if not actionable:
            if blob_backup is not None and args.require_blob_backup:
                journal.enable_blob_backup(blob_backup, create=True, verify=True)
                args.rollback_blob_verified = True
                args.rollback_blob_initial_verified = True
                reporter.emit("Rollback Blob persisted and verified (no removable assignments): " + blob_backup.destination)
            elif blob_backup is not None:
                reporter.emit("Blob upload skipped: no removable assignments; Azure mutations=0.")
            reporter.emit("{}: matched={}, removable={}, protected={}, RBAC/PIM mutations=0.".format(
                "DRY RUN" if not args.apply else "No removable assignments", len(records), len(actionable), len(blocked)))
            return 1 if args.apply and blocked else 0
        if not confirm_operation(args, "delete", len(actionable), reporter,
                                 "Keep a separate recovery operator authorized. PIM history cannot be restored."):
            journal.append("canceled")
            reporter.emit("Canceled. Azure mutations=0.")
            return 130
        client.verify_context()
        if selection.kind == "management-group" or selection.subscription_name_contains:
            fresh = resolve_scope(client, scope_from_args(args))
            if scope_document(fresh) != scope_document(selection):
                raise SafetyError("Scope hierarchy or subscription display names changed after discovery.")
        if blob_backup is not None:
            journal.enable_blob_backup(blob_backup, create=True, verify=args.require_blob_backup)
            args.rollback_blob_initial_verified = args.require_blob_backup
            reporter.emit("Rollback Blob {} before mutations: {}".format(
                "persisted and verified" if args.require_blob_backup else "uploaded", blob_backup.destination))
        client.allow_writes = True
        journal_healthy = True
        try:
            for access in pim_access:
                try:
                    verify_subscription_selection(client, selection, access.eligibility.scope)
                    access.activate(client, journal, args.poll_timeout, reporter)
                except JournalError:
                    raise
                except (SafetyError, OSError) as error:
                    pim_failed += 1
                    journal.append("pim_activation_failure", activationRequestId=access.request_id, error=str(error))
                    reporter.emit("STOP: PIM activation failed; no assignments deleted: " + str(error))
                    break
            if args.delete_workers > 1 and not pim_failed:
                reporter.emit("Parallel RBAC deletion: workers={}, per-subscription<=4, batch={}; PIM remains serial.".format(
                    args.delete_workers, args.delete_batch_size))
                deleted, skipped, failed = execute_batched_deletes(client, actionable, inventory, filters, args, reporter, journal)
            for index, record in enumerate(actionable if args.delete_workers == 1 else [], 1):
                if pim_failed:
                    break
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
        except JournalError:
            journal_healthy = False
            raise
        finally:
            try:
                if journal_healthy:
                    for access in reversed(pim_access):
                        try:
                            access.cleanup(client, journal, args.poll_timeout, reporter)
                        except JournalError:
                            journal_healthy = False
                            raise
                        except (SafetyError, OSError) as error:
                            pim_failed += 1
                            journal.append("pim_cleanup_failure", activationRequestId=access.request_id, error=str(error))
                            reporter.emit("MANUAL PIM CLEANUP REQUIRED: {} | request {} | {}".format(
                                access.eligibility.scope, access.request_id, error))
                if journal_healthy:
                    journal.append("delete_summary", deleted=deleted, skipped=skipped, failed=failed, pim_failed=pim_failed,
                                   protected=len(blocked), unprocessed=len(actionable) - deleted - skipped - failed)
                    if args.require_blob_backup:
                        checksum = journal.verify_blob_backup()
                        args.rollback_blob_verified = True
                        reporter.emit("Rollback Blob final readback VERIFIED: {} | SHA256={}".format(blob_backup.destination, checksum))
            except JournalError:
                journal_healthy = False
                raise
            finally:
                client.allow_writes = False
                if not journal_healthy:
                    for access in pim_access:
                        if access.attempted and not access.rejected:
                            reporter.emit("Journal failed; verify temporary PIM access manually: {} | request {}".format(
                                access.eligibility.scope, access.request_id))
    reporter.emit("Result: deleted={}, skipped={}, failed={}, protected={}, unprocessed={}, pim_failed={}.".format(
        deleted, skipped, failed, len(blocked), len(actionable) - deleted - skipped - failed, pim_failed))
    reporter.emit("Rollback journal: " + str(path))
    if args.include_user_details:
        result_path = path.with_name(path.stem + "-deleted-users.csv")
        users, assignments = write_deleted_users_csv(path, result_path)
        reporter.emit("Deleted-user CSV: {} | Users: {} | Successful role deletions: {}.".format(result_path, users, assignments))
    return 1 if failed or blocked or pim_failed else 0


def journal_state(rows):
    header = rows[0]
    if header.get("mode") != "apply":
        raise SafetyError("A dry-run/preview journal cannot be used to create role assignments.")
    selection = scope_from_document(header.get("selection"))
    snapshots, states = {}, {}
    complete = False
    metadata_events = {"header", "journal_recovery", "canceled", "delete_summary", "rollback_summary"} | PIM_ACCESS_EVENTS
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
    if parse_time(current["properties"].get("endDateTime"), current["id"] + " properties.endDateTime") != record.end:
        return False
    original_start = parse_time(record.properties.get("startDateTime"), record.identifier + " properties.startDateTime")
    current_start = parse_time(current["properties"].get("startDateTime"), current["id"] + " properties.startDateTime")
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
        start = parse_time(record.properties.get("startDateTime"), record.identifier + " properties.startDateTime")
        if record.end and (record.end - max(start or utc_now(), utc_now())).total_seconds() < 300:
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
    args.rollback_blob_verified = False
    args.rollback_blob_initial_verified = False
    path = journal_path(args)
    blob_backup = blob_backup_from_args(args, reporter)
    if args.apply and args.require_blob_backup and blob_backup is None:
        raise JournalError("Blob rollback backup is mandatory before applying restoration.")
    with RollbackJournal(path) as journal:
        rows = journal.read()
        header, selection, snapshots, states = journal_state(rows)
        if header.get("blobBackupEnabled") and blob_backup is None:
            reporter.emit("WARNING: Original deletion used Blob backup; this rollback is local-only unless --rollback-blob-sas-url-env is supplied.")
        pim_pending = pending_pim_access(rows)
        if header.get("pimCheck") == "operator-asserted-absent":
            reporter.emit("WARNING: The original deletion used --assume-no-pim; its PIM exclusion was not independently verified.")
        if journal.trailing_bytes:
            reporter.emit("WARNING: An incomplete trailing journal record was ignored. Pending intents are not assumed successful.")
        client = client or AzureRestClient(args.timeout, args.tenant_id, reporter)
        if header.get("tenantId", "").casefold() != client.tenant or header.get("cloud") != client.cloud:
            raise SafetyError("Rollback tenant/cloud does not match the authenticated context.")
        if args.tenant_id and args.tenant_id.casefold() != client.tenant:
            raise SafetyError("--tenant-id does not match the authenticated context.")
        pim_unresolved = check_pim_cleanup(client, pim_pending, selection, reporter)
        live_selection = selection
        if selection.kind == "management-group":
            live_selection = resolve_scope(client, ScopeSelection("management-group", selection.root, management_groups={selection.root}))
        candidates = []
        pending = 0
        for key, record in snapshots.items():
            state = states[key]
            if state["deletion"] not in ("deleted", "pending"):
                continue
            if not selection.contains(record.scope) or not live_selection.contains(record.scope):
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
            client.tenant, "APPLY" if args.apply else "DRY RUN", len(candidates), pending + pim_unresolved))
        counts = {"unresolved": pending + pim_unresolved}
        if args.apply and candidates:
            if not confirm_operation(args, "restore", len(candidates), reporter,
                                     "Reconciled pending deletions may have an uncertain original cause." if args.reconcile_pending else ""):
                reporter.emit("Canceled. No Azure mutations.")
                return 130
            client.verify_context()
            journal.prepare_append()
            if blob_backup is not None:
                journal.enable_blob_backup(blob_backup, verify=args.require_blob_backup)
                args.rollback_blob_initial_verified = args.require_blob_backup
                reporter.emit("Rollback journal synchronized to Blob before restoration.")
            client.allow_writes = True
        elif args.apply and blob_backup is not None:
            if args.require_blob_backup:
                journal.enable_blob_backup(blob_backup, verify=True)
                args.rollback_blob_initial_verified = True
                args.rollback_blob_verified = True
                reporter.emit("Rollback Blob persisted and verified; no restoration candidates.")
            else:
                reporter.emit("Blob upload skipped: no restoration candidates; Azure mutations=0.")
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
                if args.require_blob_backup:
                    checksum = journal.verify_blob_backup()
                    args.rollback_blob_verified = True
                    reporter.emit("Rollback Blob final readback VERIFIED: {} | SHA256={}".format(blob_backup.destination, checksum))
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


def environment_name(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise argparse.ArgumentTypeError("Expected an environment variable name, not a SAS URL or token.")
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
    subscription_name_contains: tuple = ()
    subscription_names: dict = field(default_factory=dict)
    subscriptions_only: bool = False

    def contains(self, scope):
        if scope == "/":
            return False
        scope = normalize_scope(scope)
        if self.subscription_name_contains or self.subscriptions_only:
            if not scope.startswith("/subscriptions/") or scope.split("/")[2] not in self.subscriptions:
                return False
        if self.kind == "management-group":
            if scope in self.management_groups or scope == self.root:
                return True
            return any(is_below(scope, "/subscriptions/" + item) for item in self.subscriptions)
        return is_below(scope, self.root) if self.include_children else scope == self.root

    def read_scopes(self):
        if self.kind == "management-group":
            groups = [] if self.subscription_name_contains or self.subscriptions_only else sorted(self.management_groups)
            return groups + ["/subscriptions/" + item for item in sorted(self.subscriptions)]
        if self.subscription_name_contains and not self.subscriptions:
            return []
        return [self.root]

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
    if args.subscriptions_only and not args.management_group:
        raise SafetyError("--subscriptions-only requires --management-group.")
    result.subscription_name_contains = tuple(args.subscription_name_contains or ())
    result.subscriptions_only = args.subscriptions_only
    return result


@dataclass
class FilterSpec:
    description_contains: tuple = ()
    description_not_contains: tuple = ()
    principal_id: tuple = ()
    principal_type: tuple = ()
    principal_name: tuple = ()
    principal_name_contains: tuple = ()
    principal_email: tuple = ()
    role_id: tuple = ()
    exclude_custom_role_name_prefix: tuple = ()
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


def matches_filters(properties, filters, kind="regular", principal=None, end=None, role_definition=None):
    if kind not in filters.assignment_kind:
        return False
    if filters.expiration != "any" and (end is not None) != (filters.expiration == "time-bound"):
        return False
    if filters.role_id and properties.get("roleDefinitionId", "").rsplit("/", 1)[-1].casefold() not in {
        value.casefold() for value in filters.role_id
    }:
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
    description = properties.get("description")
    if description is None:
        description = ""
    if (filters.description_contains or filters.description_not_contains) and not isinstance(description, str):
        raise SafetyError("Role Assignment Description is not a string; cannot evaluate the requested filters.")
    if filters.description_contains and not any(
        value.casefold() in description.casefold() for value in filters.description_contains
    ):
        return False
    if any(value.casefold() in description.casefold() for value in filters.description_not_contains):
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
    if filters.exclude_custom_role_name_prefix:
        role = validate_role_definition(role_definition, properties.get("roleDefinitionId"))
        if role["type"] == "CustomRole" and any(
            role["roleName"].casefold().startswith(value.casefold()) for value in filters.exclude_custom_role_name_prefix
        ):
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
    if selection.subscription_name_contains or selection.subscriptions_only:
        query.append("| where subscriptionId in~ (" + ", ".join(
            json.dumps(value) for value in sorted(selection.subscriptions)
        ) + ")")
    if filters.role_id:
        query.append("| where " + " or ".join(
            "tostring(properties.roleDefinitionId) endswith " + json.dumps("/" + value)
            for value in filters.role_id
        ))
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
        command.add_argument("--rollback-blob-sas-url-env", type=environment_name,
                             help="Environment variable containing a full Blob SAS URL. With --apply, mirror the local journal before mutations.")
        command.add_argument("--require-blob-backup", action="store_true",
                             help="With --apply, require remote rollback backup and verify its bytes before changes and at completion.")
        command.add_argument("--allow-ephemeral-backup", action="store_true")
        command.add_argument("--verbose", action="store_true")
        command.add_argument("--timeout", type=int, default=60, help="HTTP/CLI timeout in seconds (default: 60).")
        command.add_argument("--poll-timeout", type=int, default=300, help="PIM completion timeout in seconds.")
    roots = delete.add_mutually_exclusive_group(required=True)
    roots.add_argument("--management-group", type=nonempty, help="Management group ID, not display name.")
    roots.add_argument("--subscription", type=guid)
    roots.add_argument("--resource-id", type=nonempty)
    delete.add_argument("--subscription-name-contains", action="append", type=nonempty,
                        help="Subscription display-name substring; repeat for OR. Excludes management-group assignments.")
    delete.add_argument("--subscriptions-only", action="store_true",
                        help="With --management-group, include only descendant subscriptions/RGs/resources, not management-group assignments.")
    delete.add_argument("--resource-group", type=nonempty)
    delete.add_argument("--include-resource-descendants", action="store_true")
    delete.add_argument("--preview-file", type=nonempty,
                        help="Delete dry-run CSV path. Default: unique preview CSV; never a rollback source.")
    delete.add_argument("--include-user-details", action="store_true",
                        help="Resolve User names/UPNs/email through Graph before changes and export successful deleted-user CSV.")
    for option in ("description-contains", "principal-name", "principal-name-contains", "principal-email"):
        delete.add_argument("--" + option, action="append", type=nonempty, help="Repeat for OR values.")
    delete.add_argument("--description-not-contains", action="append", type=nonempty,
                        help="Exclude assignments containing any of these Description substrings; repeat for OR exclusions.")
    delete.add_argument("--principal-id", action="append", type=guid)
    delete.add_argument("--principal-type", action="append", type=principal_type, choices=PRINCIPAL_TYPES)
    delete.add_argument("--role-id", action="append", type=guid, help="Role definition GUID; repeat for OR.")
    delete.add_argument("--exclude-custom-role-name-prefix", action="append", type=nonempty,
                        help="Exclude CustomRole names starting with any given literal prefix. BuiltInRole assignments remain eligible.")
    delete.add_argument("--assignment-kind", action="append", choices=KINDS, help="Default: regular only.")
    delete.add_argument("--expiration", choices=("any", "permanent", "time-bound"), default="any")
    delete.add_argument("--source", choices=("arg", "arm"), default="arg",
                        help="Default: ARG candidates with bulk ARM property reads. arm lists directly; both verify again before deletion.")
    delete.add_argument("--read-workers", type=int, default=4,
                        help="Concurrent read-only ARM scope lists and missing-ID GET fallbacks (1-16, default: 4).")
    delete.add_argument("--delete-workers", type=int, default=1,
                        help="RBAC delete workers (1-32, default: 1). More than one enables batched journaling; max 4 per subscription. PIM stays serial.")
    delete.add_argument("--delete-batch-size", type=int, default=100,
                        help="Durable intent/result batch size with parallel mode (1-500, default: 100).")
    delete.add_argument("--allow-nonrestorable-pim", action="store_true")
    delete.add_argument("--allow-self-removal", action="store_true")
    delete.add_argument("--use-pim-for-owner-removal", action="store_true",
                        help="Temporarily activate the caller's existing subscription Eligible Owner/UAA, then deactivate. Never creates eligibility.")
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
    if args.command == "delete" and not 1 <= args.delete_workers <= 32:
        parser.error("--delete-workers must be between 1 and 32.")
    if args.command == "delete" and not 1 <= args.delete_batch_size <= 500:
        parser.error("--delete-batch-size must be between 1 and 500.")
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


AUTOMATION_CORE_SHA256 = '31314f5d9ab5a86664378ec6587e992b0a76ae7922957c922a0ec997c301a961'

# Azure Automation bootstrap: keep this section after the shared cleanup core.
import tempfile


AUTOMATION_PARAMETER_TYPES = {
    "command": str,
    "tenant_id": str,
    "management_group": str,
    "dry_run": bool,
    "assume_no_pim": bool,
    "save_output": bool,
    "confirm_apply": str,
    "backup_container_sas_url": str,
    "backup_container_sas_variable": str,
    "backup_container_sas_env": str,
    "restore_blob_name": str,
    "read_workers": int,
    "delete_workers": int,
    "delete_batch_size": int,
    "reconcile_pending": bool,
}


def automation_default_configuration():
    return {
        "tenant_id": "e6c9ec09-8430-4a99-bf15-242bc089b409",
        "arguments": [
            "delete", "--management-group", "KT_GPU", "--subscriptions-only", "--principal-type", "User",
            "--exclude-custom-role-name-prefix", "(KT", "--description-not-contains", "[SNOW_AUTO]",
            "--assignment-kind", "regular", "--source", "arg", "--dry-run",
        ],
        "assume_no_pim": False,
        "confirm_apply": None,
        "backup_container_sas_variable": None,
        "backup_container_sas_env": None,
        "backup_container_sas_url": None,
        "restore_blob_name": None,
        "save_output": False,
    }


class AutomationRestClient(AzureRestClient):
    def __init__(self, tenant_id, timeout=60, reporter=None):
        self.timeout = timeout
        self.reporter = reporter or Reporter()
        self.tenant = guid(tenant_id).casefold()
        self.cloud = "AzureCloud"
        self.account = {"tenantId": self.tenant}
        self.endpoints = {"arm": "https://management.azure.com", "ms-graph": "https://graph.microsoft.com"}
        self.tokens = {}
        self.token_lock = threading.Lock()
        self.allow_writes = False
        self.actor_id = None
        self.opener = urllib.request.build_opener(NoRedirect())
        self.identity_endpoint = os.environ.get("IDENTITY_ENDPOINT", "")
        self.identity_header = os.environ.get("IDENTITY_HEADER", "")
        try:
            endpoint = urllib.parse.urlsplit(self.identity_endpoint)
            if (endpoint.scheme not in ("http", "https") or endpoint.hostname not in (
                "localhost", "127.0.0.1", "::1", "169.254.169.254",
            ) or endpoint.username or endpoint.password or endpoint.fragment or not self.identity_header):
                raise ValueError("Missing trusted Automation identity endpoint/header")
        except ValueError:
            raise SafetyError("Enable the Automation account's managed identity; its trusted IDENTITY_ENDPOINT/IDENTITY_HEADER is unavailable.") from None
        self.identity_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.access_token("arm")

    def verify_context(self):
        self.access_token("arm", refresh=True)

    def access_token(self, audience, refresh=False):
        with self.token_lock:
            cached = self.tokens.get(audience)
            if cached and not refresh and cached[1] > time.time() + 120:
                return cached[0]
            parsed = urllib.parse.urlsplit(self.identity_endpoint)
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if any(key.casefold() == "resource" for key, _ in query):
                raise SafetyError("The managed identity endpoint must not contain a preset resource.")
            query.append(("resource", self.endpoints[audience] + ("/" if audience == "arm" else "")))
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))
            try:
                request = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": self.identity_header, "Metadata": "true"})
                with self.identity_opener.open(request, timeout=self.timeout) as response:
                    if response.getcode() != 200:
                        raise ValueError("Identity endpoint did not succeed")
                    data = json.loads(response.read())
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
                raise SafetyError("Automation managed identity authentication failed (HTTP {}). Secret details suppressed.".format(status)) from None
            except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError, SafetyError):
                raise SafetyError("Automation managed identity authentication failed. Secret details suppressed.") from None
            if not isinstance(data, dict) or not isinstance(data.get("access_token"), str) or not data["access_token"]:
                raise SafetyError("Managed identity returned an invalid token response.")
            token = data["access_token"]
            claims = token_claims(token)
            if not isinstance(claims, dict):
                raise SafetyError("Managed identity token claims are invalid.")
            if claims.get("tid") and str(claims["tid"]).casefold() != self.tenant:
                raise SafetyError("Managed identity token belongs to a different tenant.")
            if self.actor_id and claims.get("oid") and str(claims["oid"]).casefold() != self.actor_id.casefold():
                raise SafetyError("Managed identity principal changed during this job.")
            if audience == "arm":
                actor = claims.get("oid")
                if not isinstance(actor, str) or str(claims.get("tid", "")).casefold() != self.tenant:
                    raise SafetyError("ARM managed identity token lacks the expected tenant/principal.")
                try:
                    uuid.UUID(actor)
                except ValueError:
                    raise SafetyError("Managed identity principal ID is invalid.") from None
                if self.actor_id and actor.casefold() != self.actor_id.casefold():
                    raise SafetyError("Managed identity principal changed during this job.")
                self.actor_id = actor
            expiry = None
            for candidate in (data.get("expires_on"), claims.get("exp")):
                try:
                    parsed_expiry = float(candidate)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(parsed_expiry):
                    expiry = parsed_expiry
                    break
            if expiry is None or expiry <= time.time():
                raise SafetyError("Managed identity token has no valid future expiration.")
            self.tokens[audience] = (token, expiry)
            return token


def automation_variable_value(name):
    if not isinstance(name, str) or not name.strip():
        raise SafetyError("Invalid Automation variable name.")
    try:
        import automationassets
        from automationassets import AutomationAssetNotFound
    except ImportError:
        raise SafetyError("The runtime needs automationassets to read Automation variables.") from None
    try:
        return automationassets.get_automation_variable(name)
    except AutomationAssetNotFound:
        raise SafetyError("The requested Automation variable was not found.") from None


def automation_container_secret(config):
    asset = config.get("backup_container_sas_variable")
    environment = config.get("backup_container_sas_env")
    direct = config.get("backup_container_sas_url")
    if sum(bool(value) for value in (asset, environment, direct)) != 1:
        raise SafetyError("Specify exactly one container SAS URL, encrypted Automation variable, or environment variable.")
    if direct:
        value = direct
    elif environment:
        try:
            environment_name(environment)
        except (argparse.ArgumentTypeError, TypeError):
            raise SafetyError("Invalid container SAS environment variable name.") from None
        value = os.environ.get(environment)
    else:
        value = automation_variable_value(asset)
    if not isinstance(value, str) or not value:
        raise SafetyError("The configured container SAS is empty or is not a string.")
    return value


def automation_blob_url(container_url, blob_name):
    try:
        parsed = urllib.parse.urlsplit(container_url)
        if (not isinstance(blob_name, str) or not blob_name or any(part in ("", ".", "..") for part in blob_name.split("/"))
                or any(character in blob_name for character in "?#\\%") or any(ord(character) < 32 for character in blob_name)):
            raise ValueError("Invalid blob name")
        container = parsed.path.rstrip("/")
        if len(container.split("/")) != 2 or not container.split("/")[1]:
            raise ValueError("Expected a container URL")
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        if query.get("sr") == "b":
            raise ValueError("A blob SAS cannot authorize unique per-job backup names")
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                      container + "/" + urllib.parse.quote(blob_name, safe="/"),
                                      parsed.query, parsed.fragment))
        BlobJournalBackup(url)
        return url
    except (ValueError, TypeError, JournalError):
        raise SafetyError("Use an Azure Blob container SAS URL with read/write permissions and a safe blob name. SAS values are never logged.") from None


def automation_download_journal(url, path, timeout):
    transport = BlobJournalBackup(url, timeout)
    try:
        request = urllib.request.Request(url, headers={"x-ms-version": BLOB_API, "Accept-Encoding": "identity"})
        with transport.opener.open(request, timeout=timeout) as response, path.open("xb") as stream:
            if response.getcode() != 200:
                raise ValueError("Rollback download did not succeed")
            size = 0
            while True:
                payload = response.read(BLOB_APPEND_BYTES)
                if not payload:
                    break
                size += len(payload)
                if size > 256 * 1024 * 1024:
                    raise ValueError("Rollback journal exceeds the runbook download limit")
                stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except urllib.error.HTTPError as error:
        raise blob_http_error(error, "GET download", transport.destination) from None
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError, SafetyError):
        raise SafetyError("Rollback Blob download failed or exceeded 256 MiB. SAS details suppressed.") from None


def automation_upload_file(container, name, path, timeout, content_type):
    url = automation_blob_url(container, name)
    backup = BlobJournalBackup(url, timeout)
    with path.open("rb") as stream:
        backup.initialize(stream, create=True, content_type=content_type)
    return backup.destination


def automation_save_result(container, name, path, output, args, exit_code, error, rollback_url):
    report = {
        "completed_at": iso_time(), "command": args.command, "mode": "apply" if args.apply else "dry-run",
        "tenant_id": args.tenant_id, "management_group": getattr(args, "management_group", None),
        "exit_code": exit_code, "error": error, "core_sha256": AUTOMATION_CORE_SHA256,
        "python_runtime": sys.version.split()[0], "summary": None, "plan": None,
        "rollback_blob_url": None, "preview_blob_url": None, "preview_users": None,
        "rollback_blob_initial_verified": bool(getattr(args, "rollback_blob_initial_verified", False)),
        "rollback_blob_verified": bool(getattr(args, "rollback_blob_verified", False)),
        "deleted_users_blob_url": None, "deleted_users": None, "deleted_role_assignments": None,
    }
    if rollback_url:
        parsed = urllib.parse.urlsplit(rollback_url)
        report["rollback_blob_url"] = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    failures = []
    if output.exists() and output.suffix == ".jsonl":
        try:
            with output.open("rb") as stream:
                for line in stream:
                    if not line.endswith(b"\n"):
                        raise ValueError("Incomplete trailing journal record")
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("Invalid journal record")
                    if row.get("event") == "plan_complete":
                        report["plan"] = {key: row[key] for key in ("count", "actionable") if key in row}
                    if row.get("event") in ("delete_summary", "rollback_summary"):
                        report["summary"] = {key: value for key, value in row.items() if key not in ("event", "seq", "time")}
        except (OSError, ValueError, UnicodeError):
            failures.append("The local journal could not be fully read; do not treat its summary as complete.")
    if output.exists() and output.suffix == ".csv":
        try:
            with output.open(encoding="utf-8-sig", newline="") as stream:
                report["preview_users"] = sum(1 for _ in csv.DictReader(stream))
            report["preview_blob_url"] = automation_upload_file(
                container, name + "-preview.csv", output, args.timeout, "text/csv; charset=utf-8")
            print("Preview Blob saved: " + report["preview_blob_url"], flush=True)
        except (SafetyError, OSError, UnicodeError, csv.Error) as upload_error:
            failures.append("CSV output storage failed: " + str(upload_error))
    if args.command == "delete" and args.apply and output.exists():
        deleted_csv = output.with_name(output.stem + "-deleted-users.csv")
        try:
            if not deleted_csv.exists():
                write_deleted_users_csv(output, deleted_csv)
            with deleted_csv.open(encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames != list(DELETED_USER_COLUMNS):
                    raise ValueError("Deleted-user CSV columns are invalid")
                count, assignments = 0, 0
                for row in reader:
                    count += 1
                    assignments += int(row["deleted_role_assignments"])
            report["deleted_users"] = count
            report["deleted_role_assignments"] = assignments
            report["deleted_users_blob_url"] = automation_upload_file(
                container, name + "-deleted-users.csv", deleted_csv, args.timeout, "text/csv; charset=utf-8")
            print("Deleted-user CSV Blob saved: " + report["deleted_users_blob_url"], flush=True)
        except (SafetyError, OSError, UnicodeError, csv.Error, ValueError) as upload_error:
            failures.append("Deleted-user CSV storage failed: " + str(upload_error))
    if failures:
        report["exit_code"] = exit_code or 1
        report["output_errors"] = failures
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        destination = automation_upload_file(container, name + "-result.json", path, args.timeout, "application/json")
        print("Result Blob saved: " + destination, flush=True)
    except (SafetyError, OSError, UnicodeError) as upload_error:
        failures.append("Result output storage failed: " + str(upload_error))
    if failures:
        raise SafetyError("\n".join(failures))


def automation_configuration(argv):
    if any(not isinstance(value, str) for value in argv):
        raise SafetyError("Runbook positional arguments must be strings; input values are not logged.")
    config = {}
    for part in argv:
        part = part.strip()
        if not part:
            continue
        name, separator, value = part.partition("=")
        if (not separator or name not in AUTOMATION_PARAMETER_TYPES or not value
                or any(character.isspace() for character in part)):
            raise SafetyError("Enter one supported name=value per positional parameter, without spaces. JSON input is not supported; values are not logged.")
        if name in config:
            raise SafetyError("Duplicate Runbook parameter; specify each name only once. Values are not logged.")
        value_type = AUTOMATION_PARAMETER_TYPES[name]
        if value_type is bool:
            if value.casefold() not in ("true", "false"):
                raise SafetyError(name + " must be true or false.")
            value = value.casefold() == "true"
        elif value_type is int:
            if not re.fullmatch(r"[0-9]+", value):
                raise SafetyError(name + " must be an integer.")
            try:
                value = int(value)
            except ValueError:
                raise SafetyError(name + " must be a supported integer.") from None
        config[name] = value
    return config


def automation_main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["--help"]:
        print("No parameters: KT_GPU subscriptions-only User regular ARG dry-run; preserves (KT Custom Roles and [SNOW_AUTO] descriptions.")
        print("Enter one name=value in each positional parameter, e.g. management_group=KT_GPU and dry_run=true. Order is irrelevant.")
        print("JSON and config-variable input are not supported. Input values are never logged.")
        print("command=delete (default) or command=rollback; dry_run=true (default) or dry_run=false.")
        print("assume_no_pim=true skips PIM reads only when an operator independently verified no PIM assignments exist in the entire selected scope.")
        print("Apply always requires dry_run=false, confirm_apply=DELETE or RESTORE and a read/write container SAS.")
        print("Container SAS source: backup_container_sas_url, backup_container_sas_variable or backup_container_sas_env (exactly one).")
        print("Set save_output=true to store a result JSON and any preview CSV in the same Blob container; dry-run uploads require this opt-in.")
        print("User names/UPNs/email are resolved automatically (Graph application User.Read.All required). Apply requires verified Blob rollback storage.")
        print("Supported names: " + ", ".join(AUTOMATION_PARAMETER_TYPES))
        return 0
    internal_sas = "RBAC_AUTOMATION_JOURNAL_SAS_URL"
    previous_sas = os.environ.get(internal_sas)
    directory = None
    output = None
    result_path = None
    container = None
    output_name = None
    args = None
    error_message = None
    result = 1
    save_output = False
    preserve_recovery = False
    try:
        config = automation_configuration(argv)
        specified = set(config)
        config = dict(automation_default_configuration(), **config)
        save_output = config["save_output"]
        try:
            tenant = guid(config.get("tenant_id"))
        except (argparse.ArgumentTypeError, TypeError):
            raise SafetyError("Runbook tenant_id must be a valid tenant GUID.") from None
        command = config.get("command", "delete")
        if command not in ("delete", "rollback"):
            raise SafetyError("command must be delete or rollback.")
        if command == "rollback":
            if config.get("assume_no_pim", False):
                raise SafetyError("assume_no_pim is available for command=delete only.")
            if specified.intersection(("management_group", "read_workers", "delete_workers", "delete_batch_size")):
                raise SafetyError("Rollback uses its journal scope and serial restoration; management_group and worker overrides are delete-only.")
            arguments = ["rollback", "--dry-run"]
            if config.get("reconcile_pending", False):
                arguments.append("--reconcile-pending")
        else:
            if config.get("reconcile_pending", False):
                raise SafetyError("reconcile_pending is available only with command=rollback.")
            arguments = config["arguments"]
            if "management_group" in config:
                arguments[arguments.index("--management-group") + 1] = config["management_group"]
            for name in ("read_workers", "delete_workers", "delete_batch_size"):
                if name in config:
                    arguments.extend(["--" + name.replace("_", "-"), str(config[name])])
            if config.get("assume_no_pim", False):
                arguments.append("--assume-no-pim")
        arguments[arguments.index("--dry-run")] = "--dry-run" if config.get("dry_run", True) else "--apply"
        directory = pathlib.Path(tempfile.mkdtemp(prefix="rbac-automation-"))
        applying = "--apply" in arguments
        preserve_recovery = applying
        output = directory / ("preview.csv" if arguments[0] == "delete" and not applying else "journal.jsonl")
        option = "--preview-file" if output.suffix == ".csv" else "--rollback-file"
        args = build_parser().parse_args(arguments + [option, str(output)])
        if args.timeout <= 0 or args.poll_timeout <= 0:
            raise SafetyError("Timeouts must be positive.")
        if args.tenant_id and args.tenant_id != tenant:
            raise SafetyError("Runbook tenant_id conflicts with --tenant-id.")
        args.tenant_id = tenant
        args.require_blob_backup = True
        if args.command == "delete":
            args.include_user_details = True
            scope_from_args(args)
            if not 1 <= args.read_workers <= 16 or not 1 <= args.delete_workers <= 32 or not 1 <= args.delete_batch_size <= 500:
                raise SafetyError("Read/delete workers or delete batch size is out of range.")
            if args.use_pim_for_owner_removal:
                raise SafetyError("Managed identities cannot SelfActivate User eligibility; pregrant the runbook's required Azure RBAC permissions.")
        if args.apply and config.get("confirm_apply") != ("DELETE" if args.command == "delete" else "RESTORE"):
            raise SafetyError("Explicit confirm_apply=DELETE or RESTORE is required for Automation apply.")
        if args.apply or args.command == "rollback" or save_output:
            container = automation_container_secret(config)
            output_name = "rbac-cleanup-{}-{}".format(utc_now().strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex)
            if save_output:
                automation_blob_url(container, output_name + "-result.json")
                result_path = directory / "result.json"
        if args.apply or args.command == "rollback":
            if args.command == "rollback":
                name = config.get("restore_blob_name")
            else:
                name = output_name + ".jsonl"
            url = automation_blob_url(container, name)
            os.environ[internal_sas] = url
            args.rollback_blob_sas_url_env = internal_sas
            parsed_target = urllib.parse.urlsplit(url)
            print("Required rollback Blob target: " + urllib.parse.urlunsplit(
                (parsed_target.scheme, parsed_target.netloc, parsed_target.path, "", "")), flush=True)
        if args.command == "delete":
            print("Using Runbook default arguments: {} | User | regular | ARG | {}.".format(
                args.management_group, "APPLY" if args.apply else "DRY RUN"), flush=True)
        else:
            print("Runbook rollback | {} | scope from journal.".format("APPLY" if args.apply else "DRY RUN"), flush=True)
        client = AutomationRestClient(tenant, args.timeout, Reporter(args.verbose))
        client.reporter.emit("Automation cleanup core: " + AUTOMATION_CORE_SHA256)
        client.reporter.emit("Python runtime: " + sys.version.split()[0])
        if args.command == "rollback":
            automation_download_journal(os.environ[internal_sas], output, args.timeout)
            client.reporter.emit("Rollback input downloaded from Blob." + (
                " Dry run will not upload changes." if not args.apply else " Durable updates will append to the same Blob."))
        if args.apply:
            args.yes = True
        result = execute_delete(client, args, client.reporter) if args.command == "delete" else execute_rollback(args, client.reporter, client)
        if args.apply and result == 0 and not getattr(args, "rollback_blob_verified", False):
            raise JournalError("Rollback Blob persistence was not verified. Refusing success; preserve the local journal.")
        if args.command == "delete" and not args.apply and output.exists():
            print("BEGIN_CSV_PREVIEW", flush=True)
            print(output.read_text(encoding="utf-8-sig"), end="", flush=True)
            print("END_CSV_PREVIEW", flush=True)
        if result == 0:
            preserve_recovery = False
    except KeyboardInterrupt:
        error_message = "Interrupted. Recover pending intents from the Blob journal."
        print(error_message, file=sys.stderr)
        result = 130
    except (SafetyError, OSError) as error:
        error_message = str(error)
        print("ERROR: " + error_message, file=sys.stderr)
        result = 1
    finally:
        if save_output and container is not None and result_path is not None and args is not None:
            try:
                automation_save_result(container, output_name, result_path, output, args, result, error_message,
                                       os.environ.get(internal_sas) if args.rollback_blob_sas_url_env else None)
            except (SafetyError, OSError) as output_error:
                print("ERROR: " + str(output_error), file=sys.stderr)
                result = result or 1
                preserve_recovery = True
            except KeyboardInterrupt:
                print("Output storage interrupted; local output retained.", file=sys.stderr)
                result = 130
                preserve_recovery = True
        if previous_sas is None:
            os.environ.pop(internal_sas, None)
        else:
            os.environ[internal_sas] = previous_sas
        if directory is not None:
            deleted_csv = output.with_name(output.stem + "-deleted-users.csv") if output is not None else None
            local_files = [path for path in (output, result_path, deleted_csv) if path is not None and path.exists()]
            if preserve_recovery and local_files:
                for path in local_files:
                    label = "recovery journal" if path == output and path.suffix == ".jsonl" else "output"
                    print("Local {} retained: {}. Sandbox storage is ephemeral; recover from Blob if necessary.".format(label, path), file=sys.stderr)
            else:
                try:
                    for path in local_files:
                        path.unlink()
                    directory.rmdir()
                except OSError:
                    print("WARNING: Automation temporary directory could not be removed: " + str(directory), file=sys.stderr)
    return result


if __name__ == "__main__":
    sys.exit(automation_main())
