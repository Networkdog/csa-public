"""Read-only parallel ACR runtime CVE scanner using the current az login session."""

from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import io
import json
import multiprocessing
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, OrderedDict, deque
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, ThreadPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator, Protocol, TextIO, TypeVar


T = TypeVar("T")
R = TypeVar("R")
LOGIN_LOCK = threading.Lock()


class Cancellation(Protocol):
    def is_set(self) -> bool: ...


PARSER_STOP: Cancellation | None = None


def initialize_parser(stop: Cancellation) -> None:
    global PARSER_STOP
    PARSER_STOP = stop


def bounded_map(pool: ThreadPoolExecutor | None, function: Callable[[T], R],
                values: Iterable[T], window: int = 16,
                check: Callable[[], None] | None = None) -> Iterator[R]:
    if pool is None:
        for value in values:
            if check:
                check()
            yield function(value)
        return
    iterator = iter(values)
    pending: set[Future[R]] = set()
    try:
        while True:
            if check:
                check()
            while len(pending) < window:
                if check:
                    check()
                try:
                    value = next(iterator)
                except StopIteration:
                    break
                pending.add(pool.submit(function, value))
            if not pending:
                break
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            if check:
                check()
            for future in done:
                yield future.result()
    finally:
        for future in pending:
            future.cancel()


PHP_CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
NODE_CVE_IDS = ("CVE-2026-111497",)
CVE_IDS = (*PHP_CVE_IDS, *NODE_CVE_IDS)

PHP_FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
NODE_FIXED_VERSIONS = {(22, 23): 4, (24, 22): 1, (26, 12): 1}
NODE_BRANCH_FIXED = {
    22: (22, 23, 4),
    24: (24, 22, 1),
    26: (26, 12, 1),
}

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
IMAGE_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
}
ATTESTATION_TYPES = {"application/vnd.in-toto+json"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
VERSION = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)\Z")

PHP_VERSION_MARKER = re.compile(
    rb"X-Powered-By: PHP/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}"
    rb"[0-9A-Za-z.+~_-]{0,64})(?=[\x00\s])"
)
PHP_UTF16_VERSION_MARKER = re.compile(
    "X-Powered-By: PHP/".encode("utf-16le")
    + rb"((?:[0-9A-Za-z.+~_-]\x00){5,80})\x00\x00"
)
PHP_NAME = re.compile(
    r"(?:php(?:[0-9]+(?:\.[0-9]+)*)?(?:-(?:cli|cgi|fpm|phpdbg))?"
    r"|php(?:-fpm|-cgi|dbg)(?:[0-9]+(?:\.[0-9]+)*)?"
    r"|libphp[^/]*\.(?:so(?:\.[0-9.]+)?|dll)"
    r"|php[0-9]*(?:ts)?\.(?:exe|dll))\Z",
    re.IGNORECASE,
)

NODE_VERSION_MARKER = re.compile(
    rb"(?:node\.js/v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}(?:-[0-9A-Za-z.+~_-]{1,64})?)(?=[\x00\s])"
    rb"|https://nodejs\.org/download/release/v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}(?:-[0-9A-Za-z.+~_-]{1,64})?)/)"
)
NODE_UTF16_VERSION_MARKER = re.compile(
    "node.js/v".encode("utf-16le")
    + rb"((?:[0-9A-Za-z.+~_-]\x00){5,80})\x00\x00"
)
NODE_NAME = re.compile(
    r"(?:node(?:js)?(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?"
    r"|libnode[^/]*\.(?:so(?:\.[0-9.]+)?|dll))\Z",
    re.IGNORECASE,
)

FIELDS = (
    "RecordType", "ManagementGroup", "SubscriptionId", "SubscriptionName",
    "RegistryId", "Registry", "Repository", "Digest", "Tags", "IndexDigests",
    "IndexTags", "OS", "Architecture", "Variant", "ImageStatus", "RuntimeFamily",
    "ComponentPath", "RuntimeVersion", "PHPVersion", "NodeVersion", "Evidence",
    "LayerDigest", *CVE_IDS, "PatchVerification", "ReviewRequired",
    "CoverageComplete", "InventoryComplete", "Notes", "ScannedAtUtc",
)


class ScanError(Exception):
    pass


class AccessDeniedError(ScanError):
    def __init__(self, reason: str, context: dict[str, str] | None = None) -> None:
        super().__init__(reason)
        self.context = context or {}
        self.sealed = False

    def at(self, **context: str) -> AccessDeniedError:
        if self.sealed:
            return self
        return AccessDeniedError(self.args[0], {**context, **self.context})

    def __str__(self) -> str:
        location = ", ".join(f"{key}={value}" for key, value in self.context.items() if value)
        return str(self.args[0]) + (f" [{location}]" if location else "")


def access_denied(operation: str, status: int, hint: str, **context: str) -> AccessDeniedError:
    return AccessDeniedError(
        f"ACCESS_DENIED: {operation}; HTTP {status}. {hint}. "
        "For HTTP 403, also verify Public Network Access, Private Endpoint DNS and firewall policy",
        context,
    )


def object_value(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ScanError(f"INVALID_JSON_OBJECT: {label}")
    return dict(value)


def list_value(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ScanError(f"INVALID_JSON_ARRAY: {label}")
    return list(value)


def string_value(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScanError(f"INVALID_STRING: {label}")
    return value


def digest_value(value: object) -> str:
    digest = string_value(value, "digest")
    if not DIGEST.fullmatch(digest):
        raise ScanError("UNSUPPORTED_OR_INVALID_DIGEST: sha256 is required")
    return digest


def json_object(data: bytes, label: str) -> dict[str, object]:
    try:
        return object_value(json.loads(data), label)
    except (ValueError, UnicodeError) as exc:
        raise ScanError(f"INVALID_JSON: {label}") from exc


def run_az(arguments: list[str]) -> object:
    executable = shutil.which("az")
    if not executable:
        raise ScanError("AZURE_CLI_MISSING: install Azure CLI and run az login")
    try:
        result = subprocess.run(
            [executable, *arguments, "--only-show-errors", "--output", "json"],
            capture_output=True, encoding="utf-8", timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise ScanError(f"AZURE_CLI_EXECUTION_FAILED: {type(exc).__name__}") from exc
    if re.search(
        r"AuthorizationFailed|AuthorizationPermissionMismatch|AccessDenied|Forbidden|Unauthorized|\bdenied\b"
        r"|authentication required|insufficient (?:privileges|permissions)"
        r"|does not have authorization|AADSTS\d+|please run.{0,30}az login|not logged in",
        result.stderr, re.IGNORECASE,
    ):
        context: dict[str, str] = {}
        for flag, field in (("--subscription", "SubscriptionId"), ("--registry", "Registry")):
            if flag in arguments:
                context[field] = arguments[arguments.index(flag) + 1]
        if arguments[:2] == ["acr", "login"] and "--name" in arguments:
            context["Registry"] = arguments[arguments.index("--name") + 1]
        raise AccessDeniedError(
            "AZURE_CLI_ACCESS_DENIED: " + " ".join(arguments[:3])
            + "; check az login/tenant and Reader plus AcrPull or "
            "ABAC Repository Reader + Catalog Lister at the intended scope",
            context,
        )
    if result.returncode:
        raise ScanError(
            "AZURE_CLI_FAILED: check az login, selected subscription, "
            "registry catalog/read permissions and network access"
        )
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise ScanError("AZURE_CLI_INVALID_JSON") from exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_response(response: http.client.HTTPResponse, limit: int, label: str) -> bytes:
    try:
        with response:
            raw = response.read(limit + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise ScanError(f"{label}_READ_FAILED: {type(exc).__name__}") from exc
    if len(raw) > limit:
        raise ScanError(f"{label}_TOO_LARGE")
    return raw


@dataclass(frozen=True)
class ManifestRef:
    digest: str
    tags: tuple[str, ...] = ()


class Registry(Protocol):
    def repositories(self) -> Iterator[str]: ...
    def manifests(self, repository: str) -> Iterator[ManifestRef]: ...
    def manifest(self, repository: str, digest: str) -> dict[str, object]: ...
    def blob(self, repository: str, descriptor: dict[str, object],
             destination: BinaryIO, limit: int) -> None: ...


CLOUDS = {
    "AzureCloud": ("https://management.azure.com", "https://containerregistry.azure.net/.default"),
    "AzureUSGovernment": ("https://management.usgovcloudapi.net", "https://containerregistry.azure.us/.default"),
    "AzureChinaCloud": ("https://management.chinacloudapi.cn", "https://containerregistry.azure.cn/.default"),
}


class AzureCliAuth:
    def __init__(self, cloud: str = "AzureCloud",
                 timeout: int = 60) -> None:
        self.arm, self.acr_scope = CLOUDS[cloud]
        self.timeout = timeout
        self.guard = threading.RLock()
        self.tokens: dict[str, tuple[str, int]] = {}
        self.http = threading.local()
        self.stop: threading.Event | None = None

    def token(self, scope: str) -> str:
        with self.guard:
            if self.stop and self.stop.is_set():
                raise ScanError("CANCELLED")
            cached = self.tokens.get(scope)
            if cached and cached[1] > time.time() + 60:
                return cached[0]
            result = object_value(run_az(["account", "get-access-token", "--scope", scope]), "CLI access token")
            token = string_value(result.get("accessToken"), "accessToken")
            expires = result.get("expires_on")
            if isinstance(expires, str) and expires.isdigit():
                expires = int(expires)
            if type(expires) is not int or expires <= time.time():
                raise ScanError("INVALID_CLI_TOKEN_EXPIRATION: update Azure CLI and run az login")
            self.tokens[scope] = token, expires
            return token

    def arm_json(self, url: str) -> dict[str, object]:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.netloc != urllib.parse.urlsplit(self.arm).netloc
                or parsed.username or parsed.password or parsed.fragment):
            raise ScanError("UNTRUSTED_ARM_URL")
        if not hasattr(self.http, "opener"):
            self.http.opener = urllib.request.build_opener(NoRedirect())
        scope = self.arm + "/.default"
        for attempt in range(4):
            if self.stop and self.stop.is_set():
                raise ScanError("CANCELLED")
            request = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token(scope)})
            try:
                raw = read_response(self.http.opener.open(request, timeout=self.timeout),
                                    4 * 1024 * 1024, "ARM_RESPONSE")
                return json_object(raw, "ARM response")
            except urllib.error.HTTPError as exc:
                status = exc.code
                retry_after = exc.headers.get("Retry-After", "")
                exc.close()
                if status == 401 and attempt == 0:
                    with self.guard:
                        self.tokens.pop(scope, None)
                    continue
                if status in (401, 403):
                    context: dict[str, str] = {}
                    sub = re.search(r"/subscriptions/([^/]+)", parsed.path, re.IGNORECASE)
                    if sub:
                        context["SubscriptionId"] = sub[1]
                    hint = ("Reader: Microsoft.Management/managementGroups/descendants/read"
                            if parsed.path.endswith("/descendants")
                            else "Reader: Microsoft.ContainerRegistry/registries/read on the requested scope")
                    raise access_denied(f"ARM GET {parsed.path}", status, hint, **context) from None
                if status in (429, 500, 502, 503, 504) and attempt < 3:
                    delay = min(int(retry_after), 30) if retry_after.isdigit() else 2 ** attempt
                    print(f"Retry ARM HTTP {status} in {delay}s", file=sys.stderr)
                    if self.stop:
                        if self.stop.wait(delay):
                            raise ScanError("CANCELLED")
                    else:
                        time.sleep(delay)
                    continue
                raise ScanError(f"ARM_HTTP_{status}: verify identity, scope and Reader permissions") from None
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                raise ScanError(f"ARM_NETWORK_FAILED: {type(exc).__name__}") from None
        raise ScanError("ARM_REQUEST_FAILED")

    def resolve_registry(self, name: str, subscription: str | None,
                         resource_id: str | None) -> dict[str, object]:
        if resource_id:
            return self.arm_json(f"{self.arm}{resource_id}?api-version=2023-07-01")
        subscription = subscription or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not subscription:
            account = object_value(run_az(["account", "show"]), "active Azure CLI account")
            subscription = string_value(account.get("id"), "active subscription id")
        prefix = f"{self.arm}/subscriptions/{urllib.parse.quote(subscription, safe='')}"
        for entry in arm_pages(prefix + "/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01",
                               auth=self):
            if entry.get("name") == name:
                return entry
        raise ScanError("REGISTRY_NOT_FOUND_IN_SUBSCRIPTION")

def create_auth(args: argparse.Namespace) -> AzureCliAuth:
    return AzureCliAuth(args.cloud, args.timeout)


class AzureRegistry:
    def __init__(self, name: str, timeout: int = 60, subscription: str | None = None,
                 auth: AzureCliAuth | None = None, resource_id: str | None = None,
                 stop: threading.Event | None = None) -> None:
        self.name = name
        self.subscription = subscription
        self.auth = auth
        self.resource_id = resource_id
        self.timeout = timeout
        self._http = threading.local()
        self._auth_lock = threading.RLock()
        self.stop = stop
        self.server = ""
        self.refresh_token = ""
        self.tokens: dict[tuple[str, str], tuple[str, float]] = {}
        self._login()

    @property
    def opener(self) -> urllib.request.OpenerDirector:
        if not hasattr(self._http, "opener"):
            self._http.opener = urllib.request.build_opener(NoRedirect())
        return self._http.opener

    def _cli(self, arguments: list[str]) -> object:
        if self.stop and self.stop.is_set():
            raise ScanError("CANCELLED")
        if self.subscription:
            arguments = [*arguments, "--subscription", self.subscription]
        try:
            return run_az(arguments)
        except AccessDeniedError as exc:
            raise exc.at(Registry=self.name, SubscriptionId=self.subscription or "",
                         RegistryId=self.resource_id or "")

    def _login(self) -> None:
        with self._auth_lock, LOGIN_LOCK:
            try:
                self._login_locked()
            except AccessDeniedError as exc:
                raise exc.at(Registry=self.name, SubscriptionId=self.subscription or "",
                             RegistryId=self.resource_id or "")

    def _login_locked(self) -> None:
        if self.auth:
            self._identity_login()
            return
        login = object_value(
            self._cli(["acr", "login", "--name", self.name, "--expose-token"]),
            "Azure CLI login response",
        )
        server = string_value(login.get("loginServer"), "loginServer").lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.azurecr\.(?:io|cn|us)", server):
            raise ScanError("UNEXPECTED_LOGIN_SERVER: an Azure Container Registry host is required")
        if self.server and self.server != server:
            raise ScanError("LOGIN_SERVER_CHANGED")
        self.server = server
        self.refresh_token = string_value(login.get("accessToken"), "ACR refresh token")
        self.tokens.clear()

    def _identity_login(self) -> None:
        if self.stop and self.stop.is_set():
            raise ScanError("CANCELLED")
        auth = self.auth
        if auth is None:
            raise ScanError("AZURE_IDENTITY_REQUIRED")
        metadata = auth.resolve_registry(self.name, self.subscription, self.resource_id)
        resource_id = string_value(metadata.get("id"), "registry id")
        match = re.fullmatch(
            r"/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/[^/]+"
            rf"/providers/Microsoft.ContainerRegistry/registries/{re.escape(self.name)}",
            resource_id, re.IGNORECASE,
        )
        if metadata.get("name") != self.name or not match:
            raise ScanError("REGISTRY_IDENTITY_MISMATCH")
        self.resource_id = resource_id
        self.subscription = match[1]
        server = string_value(
            object_value(metadata.get("properties"), "registry properties").get("loginServer"), "loginServer",
        ).lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.azurecr\.(?:io|cn|us)", server):
            raise ScanError("UNEXPECTED_LOGIN_SERVER")
        if self.server and self.server != server:
            raise ScanError("LOGIN_SERVER_CHANGED")
        self.server = server
        for attempt in range(2):
            data = urllib.parse.urlencode({
                "grant_type": "access_token", "service": server,
                "access_token": auth.token(auth.acr_scope),
            }).encode("ascii")
            request = urllib.request.Request(f"https://{server}/oauth2/exchange", data=data,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                raw = read_response(self._open(request), 1024 * 1024, "ACR_EXCHANGE")
                break
            except urllib.error.HTTPError as exc:
                status = exc.code
                exc.close()
                if status == 401 and attempt == 0:
                    with auth.guard:
                        auth.tokens.pop(auth.acr_scope, None)
                    continue
                if status in (401, 403):
                    raise self._denied("ACR Entra token exchange", status) from None
                raise ScanError(f"ACR_EXCHANGE_HTTP_{status}: verify identity and ACR data roles") from None
        self.refresh_token = string_value(json_object(raw, "ACR exchange").get("refresh_token"), "refresh_token")
        self.tokens.clear()

    def _open(self, request: urllib.request.Request, blob: bool = False) -> http.client.HTTPResponse:
        for _ in range(4):
            if self.stop and self.stop.is_set():
                raise ScanError("CANCELLED")
            try:
                return self.opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                location = exc.headers.get("Location")
                if exc.code not in (301, 302, 303, 307, 308) or not location:
                    raise
                destination = urllib.parse.urljoin(request.full_url, location)
                try:
                    parsed = urllib.parse.urlsplit(destination)
                    host = parsed.hostname or ""
                    port = parsed.port
                except ValueError:
                    exc.close()
                    raise ScanError("INVALID_HTTP_REDIRECT_BLOCKED") from None
                allowed = host == self.server or host.endswith((
                                ".privatelink.azurecr.io", ".privatelink.azurecr.cn", ".privatelink.azurecr.us",
                                ".data.azurecr.io", ".data.azurecr.cn", ".data.azurecr.us",
                                ".blob.core.windows.net", ".blob.core.chinacloudapi.cn",
                                ".blob.core.usgovcloudapi.net",
                            ))
                if (not blob or not allowed or parsed.scheme != "https"
                        or parsed.username or parsed.password or port not in (None, 443)):
                    exc.close()
                    raise ScanError("UNSAFE_HTTP_REDIRECT_BLOCKED") from None
                headers = {
                    key: value for key, value in request.header_items()
                    if key.lower() not in ("proxy-authorization", "host")
                    and (host == self.server or key.lower() != "authorization")
                }
                exc.close()
                request = urllib.request.Request(destination, headers=headers)
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                raise ScanError(f"NETWORK_ERROR: {type(exc).__name__}") from exc
        raise ScanError("TOO_MANY_HTTP_REDIRECTS")

    def _token(self, repository: str, permission: str = "pull") -> str:
        with self._auth_lock:
            return self._token_locked(repository, permission)

    def _token_locked(self, repository: str, permission: str) -> str:
        key = repository, permission
        cached = self.tokens.get(key)
        if cached and cached[1] > time.monotonic():
            return cached[0]
        for attempt in range(2):
            data = urllib.parse.urlencode({
                "grant_type": "refresh_token",
                "service": self.server,
                "scope": f"repository:{repository}:{permission}" if repository else "registry:catalog:*",
                "refresh_token": self.refresh_token,
            }).encode("ascii")
            request = urllib.request.Request(
                f"https://{self.server}/oauth2/token", data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
            )
            try:
                raw = read_response(self._open(request), 1024 * 1024, "TOKEN_RESPONSE")
            except urllib.error.HTTPError as exc:
                status = exc.code
                exc.close()
                if status == 401 and attempt == 0:
                    self._login()
                    continue
                if status in (401, 403):
                    raise self._denied("ACR scoped token exchange", status, repository, permission) from None
                raise ScanError(f"ACR_TOKEN_HTTP_{status}: verify pull permissions and az login") from None
            token = string_value(json_object(raw, "ACR token").get("access_token"), "access_token")
            self.tokens[key] = (token, time.monotonic() + 300)
            return token
        raise ScanError("ACR_TOKEN_REFRESH_FAILED")

    def _get(self, repository: str, path: str, blob: bool = False,
             permission: str = "pull") -> http.client.HTTPResponse:
        refreshed = False
        for attempt in range(4):
            request = urllib.request.Request(
                f"https://{self.server}{path}",
                headers={
                    "Authorization": f"Bearer {self._token(repository, permission)}",
                    "Accept": ", ".join(sorted(INDEX_TYPES | IMAGE_TYPES)),
                    "User-Agent": "csa-acr-runtime-cves/1.0",
                },
            )
            try:
                return self._open(request, blob=blob)
            except urllib.error.HTTPError as exc:
                status = exc.code
                retry_after = exc.headers.get("Retry-After", "")
                exc.close()
                if status == 401 and not refreshed:
                    refreshed = True
                    self._login()
                    continue
                if status in (401, 403):
                    error = self._denied("ACR read", status, repository, permission)
                    if "/manifests/" in path:
                        error = error.at(Digest=path.rsplit("/", 1)[1])
                    elif "/blobs/" in path:
                        error = error.at(LayerDigest=path.rsplit("/", 1)[1])
                    raise error from None
                if status in (429, 500, 502, 503, 504) and attempt < 3:
                    delay = min(int(retry_after), 30) if retry_after.isdigit() else 2 ** attempt
                    print(f"Retry registry HTTP {status} in {delay}s", file=sys.stderr)
                    if self.stop:
                        if self.stop.wait(delay):
                            raise ScanError("CANCELLED")
                    else:
                        time.sleep(delay)
                    continue
                raise ScanError(f"REGISTRY_HTTP_{status}: manifest/blob could not be read") from None
        raise ScanError("REGISTRY_AUTHENTICATION_FAILED")

    def _denied(self, operation: str, status: int, repository: str = "",
                permission: str = "pull") -> AccessDeniedError:
        hint = ("AcrPull (legacy), or Container Registry Repository Catalog Lister (ABAC)"
                if not repository else
                "AcrPull (legacy), or Container Registry Repository Reader (ABAC): "
                + ("repositories/metadata/read" if permission == "metadata_read"
                   else "repositories/content/read"))
        return access_denied(operation, status, hint, Registry=self.name, Repository=repository,
                             SubscriptionId=self.subscription or "", RegistryId=self.resource_id or "")

    def repositories(self) -> Iterator[str]:
        if self.auth:
            for page in self._data_pages("", "/acr/v1/_catalog?n=100"):
                for value in list_value(page.get("repositories"), "repositories"):
                    yield string_value(value, "repository")
            return
        result = list_value(self._cli(["acr", "repository", "list", "--name", self.name]), "repositories")
        for item in result:
            yield string_value(item, "repository")

    def manifests(self, repository: str) -> Iterator[ManifestRef]:
        if self.auth:
            for page in self._data_pages(
                repository, f"/acr/v1/{urllib.parse.quote(repository, safe='/')}/_manifests?n=100",
                "metadata_read",
            ):
                for value in list_value(page.get("manifests"), "manifests"):
                    yield self._manifest_reference(value)
            return
        items = list_value(self._cli([
            "acr", "manifest", "list-metadata", "--registry", self.name,
            "--name", repository, "--query", "[]",
        ]), "manifests")
        for item in items:
            yield self._manifest_reference(item)

    @staticmethod
    def _manifest_reference(item: object) -> ManifestRef:
        entry = object_value(item, "manifest metadata")
        tags = entry.get("tags")
        return ManifestRef(
            digest_value(entry.get("digest")),
            tuple(string_value(tag, "tag") for tag in list_value(tags, "tags")) if tags is not None else (),
        )

    def _data_pages(self, repository: str, path: str, permission: str = "pull") -> Iterator[dict[str, object]]:
        initial = urllib.parse.urlsplit(path).path
        seen: set[str] = set()
        while path:
            if path in seen:
                raise ScanError("REPEATED_ACR_NEXT_LINK")
            seen.add(path)
            response = self._get(repository, path, permission=permission)
            link = response.headers.get("Link", "")
            page = json_object(read_response(response, 4 * 1024 * 1024, "ACR_METADATA"), "ACR metadata")
            yield page
            matches = re.findall(r'<([^>]+)>\s*;\s*rel="?next"?', link, re.IGNORECASE)
            if not matches:
                if link:
                    raise ScanError("UNSUPPORTED_ACR_LINK_HEADER")
                break
            if len(matches) != 1:
                raise ScanError("INVALID_ACR_NEXT_LINK")
            parsed = urllib.parse.urlsplit(urllib.parse.urljoin(f"https://{self.server}{path}", matches[0]))
            if (parsed.scheme != "https" or parsed.netloc != self.server or parsed.path != initial
                    or parsed.username or parsed.password or parsed.fragment):
                raise ScanError("UNTRUSTED_ACR_NEXT_LINK")
            path = parsed.path + ("?" + parsed.query if parsed.query else "")

    def manifest(self, repository: str, digest: str) -> dict[str, object]:
        digest_value(digest)
        path = f"/v2/{urllib.parse.quote(repository, safe='/')}/manifests/{digest}"
        raw = read_response(self._get(repository, path), 4 * 1024 * 1024, "MANIFEST")
        if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
            raise ScanError("MANIFEST_DIGEST_MISMATCH")
        return json_object(raw, "manifest")

    def blob(self, repository: str, descriptor: dict[str, object],
             destination: BinaryIO, limit: int) -> None:
        digest = digest_value(descriptor.get("digest"))
        size = descriptor.get("size")
        if type(size) is not int or size < 0:
            raise ScanError("INVALID_BLOB_SIZE")
        if size > limit:
            raise ScanError("BLOB_SIZE_LIMIT_EXCEEDED")
        path = f"/v2/{urllib.parse.quote(repository, safe='/')}/blobs/{digest}"
        for attempt in range(3):
            checksum = hashlib.sha256()
            received = 0
            destination.seek(0)
            destination.truncate(0)
            try:
                with self._get(repository, path, blob=True) as response:
                    while chunk := response.read(1024 * 1024):
                        if self.stop and self.stop.is_set():
                            raise ScanError("CANCELLED")
                        received += len(chunk)
                        if received > limit:
                            raise ScanError("BLOB_SIZE_LIMIT_EXCEEDED")
                        checksum.update(chunk)
                        destination.write(chunk)
            except (OSError, http.client.HTTPException) as exc:
                if attempt < 2:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise ScanError(f"BLOB_READ_FAILED: {type(exc).__name__}") from exc
            if received != size or "sha256:" + checksum.hexdigest() != digest:
                raise ScanError("BLOB_SIZE_OR_DIGEST_MISMATCH")
            return


@dataclass
class Target:
    repository: str
    digest: str
    manifest: dict[str, object]
    tags: set[str] = field(default_factory=set)
    indexes: set[str] = field(default_factory=set)
    index_tags: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Issue:
    repository: str
    digest: str
    message: str


@dataclass
class Inventory:
    targets: dict[tuple[str, str], Target] = field(default_factory=dict)
    listed: set[tuple[str, str]] = field(default_factory=set)
    issues: list[Issue] = field(default_factory=list)


def catalog(registry: Registry, parallel: Parallelism | None = None) -> tuple[dict[str, list[ManifestRef]], list[Issue]]:
    result: dict[str, list[ManifestRef]] = {}
    issues: list[Issue] = []
    def read(repository: str) -> tuple[str, list[ManifestRef], Issue | None]:
        try:
            if parallel:
                parallel.check()
            return repository, list(registry.manifests(repository)), None
        except AccessDeniedError as exc:
            error = exc.at(Repository=repository)
            if parallel:
                parallel.deny(error)
            raise error
        except ScanError as exc:
            return repository, [], Issue(repository, "", str(exc))

    try:
        for repository, references, issue in bounded_map(
            parallel.metadata if parallel else None, read, registry.repositories(),
            check=parallel.check if parallel else None,
        ):
            if issue:
                issues.append(issue)
            else:
                result[repository] = references
    except AccessDeniedError:
        raise
    except ScanError as exc:
        issues.append(Issue("", "", str(exc)))
    return result, issues


def inventory(registry: Registry, parallel: Parallelism | None = None) -> Inventory:
    repositories, issues = catalog(registry, parallel)
    result = Inventory(issues=issues)
    cache: dict[tuple[str, str], Future[dict[str, object]]] = {}
    guard = threading.RLock()

    def fetch(repository: str, digest: str) -> dict[str, object]:
        with guard:
            key = repository, digest
            owner = key not in cache
            future = cache.setdefault(key, Future())
        if owner:
            try:
                future.set_result(registry.manifest(repository, digest))
            except BaseException as exc:
                future.set_exception(exc)
                raise
        return future.result()

    def expand(repository: str, digest: str, tags: set[str], ancestors: tuple[str, ...],
               inherited_tags: set[str]) -> None:
        if digest in ancestors or len(ancestors) >= 16:
            raise ScanError("MANIFEST_INDEX_CYCLE_OR_DEPTH_LIMIT")
        key = (repository, digest)
        manifest = fetch(repository, digest)
        media_type = string_value(manifest.get("mediaType"), "manifest mediaType")
        if media_type in INDEX_TYPES:
            children = list_value(manifest.get("manifests"), "index manifests")
            if not children:
                raise ScanError("EMPTY_MANIFEST_INDEX")
            for value in children:
                child = object_value(value, "index child")
                child_digest = digest_value(child.get("digest"))
                try:
                    expand(repository, child_digest, set(), (*ancestors, digest),
                           inherited_tags | tags)
                except AccessDeniedError:
                    raise
                except ScanError as exc:
                    with guard:
                        result.issues.append(Issue(repository, child_digest, str(exc)))
            return
        with guard:
            target = result.targets.setdefault(key, Target(repository, digest, manifest))
            target.tags.update(tags)
            target.indexes.update(ancestors)
            target.index_tags.update(inherited_tags)

    def read(item: tuple[str, ManifestRef]) -> None:
        repository, reference = item
        with guard:
            result.listed.add((repository, reference.digest))
        try:
            if parallel:
                parallel.check()
            expand(repository, reference.digest, set(reference.tags), (), set())
        except AccessDeniedError as exc:
            error = exc.at(Repository=repository, Digest=reference.digest)
            if parallel:
                parallel.deny(error)
            raise error
        except ScanError as exc:
            with guard:
                result.issues.append(Issue(repository, reference.digest, str(exc)))
    entries = ((repository, ref) for repository, manifests in repositories.items() for ref in manifests)
    for _ in bounded_map(parallel.metadata if parallel else None, read, entries,
                         check=parallel.check if parallel else None):
        pass
    return result


def path_value(name: str) -> str:
    if "\x00" in name or "\\" in name or name.startswith("/"):
        raise ScanError("UNSUPPORTED_LAYER_PATH")
    normalized = posixpath.normpath(name)
    if normalized == ".." or normalized.startswith("../"):
        raise ScanError("UNSAFE_LAYER_PATH")
    return normalized.removeprefix("./")


def assess_php_version(version: str) -> str:
    match = VERSION.fullmatch(version)
    if not match:
        return "UNKNOWN"
    major, minor, patch = map(int, match.groups())
    fixed = PHP_FIXED_VERSIONS.get((major, minor))
    if fixed is None:
        return "UNKNOWN"
    return "AFFECTED_UPSTREAM_RANGE" if patch < fixed else "FIXED_UPSTREAM_RANGE"


def assess_node_version(version: str) -> str:
    match = VERSION.fullmatch(version)
    if not match:
        return "UNKNOWN"
    major, minor, patch = map(int, match.groups())
    min_fixed = NODE_BRANCH_FIXED.get(major)
    if min_fixed is None:
        return "UNKNOWN"
    return "AFFECTED_UPSTREAM_RANGE" if (major, minor, patch) < min_fixed else "FIXED_UPSTREAM_RANGE"


def assess_version(version: str, family: str = "PHP") -> str:
    if family == "PHP":
        return assess_php_version(version)
    if family == "NODE":
        return assess_node_version(version)
    return "UNKNOWN"


@dataclass(frozen=True)
class Component:
    path: str
    version: str
    evidence: str
    layer: str
    note: str = ""
    family: str = "PHP"


def inspect_binary(path: str, stream: BinaryIO, size: int, layer: str, limit: int) -> Component | None:
    prefix = stream.read(min(size, 4))
    native = prefix.startswith(b"\x7fELF") or prefix.startswith(b"MZ")
    basename = posixpath.basename(path)
    php_named = bool(PHP_NAME.fullmatch(basename))
    node_named = bool(NODE_NAME.fullmatch(basename))
    if not native and not php_named and not node_named:
        return None
    if size > limit:
        family = "NODE" if (node_named and not php_named) else ("PHP" if php_named else "UNKNOWN")
        return Component(path, "", "SIZE_LIMIT", layer, "Native/candidate file was not fully inspected", family)
    data = prefix + stream.read(size - len(prefix))
    if len(data) != size:
        raise ScanError("TRUNCATED_LAYER_FILE")

    php_versions = sorted({
        match.decode("ascii")
        for match in PHP_VERSION_MARKER.findall(data)
    })
    if native:
        php_versions = sorted(set(php_versions) | {
            match.decode("utf-16le") for match in PHP_UTF16_VERSION_MARKER.findall(data)
        })
    php_hints = php_named or b"Zend Engine" in data or b"X-Powered-By: PHP/" in data

    node_versions = sorted({
        (m[0] or m[1]).decode("ascii")
        for m in NODE_VERSION_MARKER.findall(data)
    })
    if native:
        node_versions = sorted(set(node_versions) | {
            match.decode("utf-16le") for match in NODE_UTF16_VERSION_MARKER.findall(data)
        })
    node_hints = node_named or b"node.js/v" in data or b"https://nodejs.org/download/release/v" in data

    if php_versions or (php_hints and not node_versions):
        if not native and php_versions:
            return Component(path, "", "NON_NATIVE_PHP_CANDIDATE", layer,
                             "Text/wrapper metadata is not executable-version proof", "PHP")
        if len(php_versions) == 1:
            return Component(path, php_versions[0], "NATIVE_SAPI_VERSION_HEADER", layer, "", "PHP")
        if len(php_versions) > 1:
            return Component(path, "", "CONFLICTING_VERSION_HEADERS", layer, "; ".join(php_versions), "PHP")
        if php_hints:
            return Component(path, "", "PHP_CANDIDATE_WITHOUT_VERSION", layer, "", "PHP")

    if node_versions or node_hints:
        if not native and node_versions:
            return Component(path, "", "NON_NATIVE_NODE_CANDIDATE", layer,
                             "Text/wrapper metadata is not executable-version proof", "NODE")
        if len(node_versions) == 1:
            return Component(path, node_versions[0], "NATIVE_NODE_VERSION_MARKER", layer, "", "NODE")
        if len(node_versions) > 1:
            return Component(path, "", "CONFLICTING_VERSION_HEADERS", layer, "; ".join(node_versions), "NODE")
        if node_hints:
            return Component(path, "", "NODE_CANDIDATE_WITHOUT_VERSION", layer, "", "NODE")

    return None


@dataclass(frozen=True)
class Change:
    path: str
    kind: str
    component: Component | None = None
    target: str = ""


@dataclass(frozen=True)
class Layer:
    whiteouts: tuple[str, ...]
    opaque: tuple[str, ...]
    changes: tuple[Change, ...]


def scan_layer(stream: BinaryIO, digest: str, file_limit: int, unpacked_limit: int,
               stop: Cancellation | None = None) -> Layer:
    whiteouts: list[str] = []
    opaque: list[str] = []
    changes: list[Change] = []
    unpacked = 0
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as archive:
            for member in archive:
                if stop and stop.is_set():
                    raise ScanError("CANCELLED")
                path = path_value(member.name)
                if path == ".":
                    continue
                if member.size < 0:
                    raise ScanError("NEGATIVE_LAYER_FILE_SIZE")
                unpacked += member.size
                if unpacked > unpacked_limit:
                    raise ScanError("UNPACKED_LAYER_SIZE_LIMIT_EXCEEDED")
                directory, basename = posixpath.split(path)
                if basename == ".wh..wh..opq":
                    opaque.append(directory)
                elif basename.startswith(".wh."):
                    whiteouts.append(posixpath.join(directory, basename[4:]))
                elif member.isdir():
                    changes.append(Change(path, "directory"))
                elif member.isfile():
                    source = archive.extractfile(member)
                    if source is None:
                        raise ScanError("LAYER_FILE_COULD_NOT_BE_READ")
                    with source:
                        component = inspect_binary(path, source, member.size, digest, file_limit)
                    changes.append(Change(path, "file", component))
                elif member.islnk():
                    changes.append(Change(path, "hardlink", target=path_value(member.linkname)))
                elif member.issym():
                    changes.append(Change(path, "symlink", target=member.linkname))
                else:
                    changes.append(Change(path, "other"))
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise ScanError(f"UNREADABLE_OR_UNSUPPORTED_LAYER: {type(exc).__name__}") from exc
    return Layer(tuple(whiteouts), tuple(opaque), tuple(changes))


def remove_path(state: dict[str, Component], path: str, children_only: bool = False) -> None:
    prefix = path + "/" if path else ""
    for existing in list(state):
        if (not children_only and existing == path) or existing.startswith(prefix):
            del state[existing]


def apply_layer(state: dict[str, Component], links: set[str], layer: Layer) -> None:
    for path in layer.whiteouts:
        remove_path(state, path)
        links.difference_update({link for link in links if link == path or link.startswith(path + "/")})
    for path in layer.opaque:
        remove_path(state, path, children_only=True)
        prefix = path + "/" if path else ""
        links.difference_update({link for link in links if link.startswith(prefix)})
    pending: list[Change] = []
    for change in layer.changes:
        if any(change.path.startswith(link + "/") for link in links):
            raise ScanError("SYMLINK_PARENT_REQUIRES_MANUAL_REVIEW")
        if change.kind == "directory":
            state.pop(change.path, None)
            links.discard(change.path)
            continue
        remove_path(state, change.path)
        links.discard(change.path)
        if change.component:
            state[change.path] = change.component
        elif change.kind == "hardlink":
            if change.target in state:
                state[change.path] = replace(state[change.target], path=change.path)
            else:
                pending.append(change)
        elif change.kind == "symlink":
            links.add(change.path)
    for change in pending:
        if change.target in state:
            state[change.path] = replace(state[change.target], path=change.path)
        else:
            basename = posixpath.basename(change.path)
            if PHP_NAME.fullmatch(basename):
                state[change.path] = Component(change.path, "", "UNRESOLVED_PHP_HARDLINK", "", "", "PHP")
            elif NODE_NAME.fullmatch(basename):
                state[change.path] = Component(change.path, "", "UNRESOLVED_NODE_HARDLINK", "", "", "NODE")


@dataclass(frozen=True)
class Limits:
    layer: int = 1024 * 1024 * 1024
    file: int = 256 * 1024 * 1024
    unpacked: int = 8 * 1024 * 1024 * 1024


@dataclass
class Analysis:
    status: str
    os: str = ""
    architecture: str = ""
    variant: str = ""
    components: list[Component] = field(default_factory=list)
    complete: bool = True
    notes: str = ""


def parse_layer_file(path: str, digest: str, file_limit: int, unpacked_limit: int) -> Layer:
    with open(path, "rb") as stream:
        return scan_layer(stream, digest, file_limit, unpacked_limit, PARSER_STOP)


class Parallelism:
    def __init__(self, workers: int = 8, registry_workers: int = 4,
                 metadata_workers: int = 8, parse_workers: int = 2,
                 cache_mib: int = 256, process_parsers: bool = True) -> None:
        self.workers = workers
        self.stop = threading.Event()
        self.registries = ThreadPoolExecutor(registry_workers, thread_name_prefix="registry")
        self.metadata = ThreadPoolExecutor(metadata_workers, thread_name_prefix="metadata")
        self.images = ThreadPoolExecutor(workers, thread_name_prefix="image")
        self.layers = ThreadPoolExecutor(workers, thread_name_prefix="layer")
        context = multiprocessing.get_context("spawn")
        try:
            self.parser_stop = context.Event() if process_parsers else None
            self.parsers = (ProcessPoolExecutor(
                parse_workers, mp_context=context, initializer=initialize_parser,
                initargs=(self.parser_stop,),
            ) if process_parsers else None)
        except (OSError, RuntimeError) as exc:
            raise ScanError(f"CPU_PARSER_START_FAILED: {type(exc).__name__}; try --thread-parsers") from exc
        self.parse_slots = threading.BoundedSemaphore(parse_workers)
        self.layer_slots = threading.BoundedSemaphore(workers * 2)
        self.cache_limit = cache_mib * 1024 * 1024
        self.cache_bytes = 0
        self.cache: OrderedDict[tuple[str, int, str], tuple[Layer, int]] = OrderedDict()
        self.inflight: dict[tuple[int, str, tuple[str, int, str]], Future[Layer]] = {}
        self.guard = threading.RLock()
        self.report_lock = threading.RLock()
        self.first_access_error: AccessDeniedError | None = None

    def deny(self, error: AccessDeniedError) -> None:
        with self.guard:
            if self.first_access_error is None:
                error.sealed = True
                self.first_access_error = error
                print(f"Stopping scan: {error}", file=sys.stderr, flush=True)
            self.stop.set()
            if self.parser_stop:
                self.parser_stop.set()

    def check(self) -> None:
        if self.stop.is_set():
            with self.guard:
                if self.first_access_error:
                    raise self.first_access_error
            raise ScanError("CANCELLED")

    def __enter__(self) -> Parallelism:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if isinstance(exc_value, AccessDeniedError):
            self.deny(exc_value)
        elif exc_type is not None:
            self.stop.set()
            if self.parser_stop:
                self.parser_stop.set()
        # Cancel all queues before waiting for coordinators that depend on those pools.
        for pool in (self.registries, self.images, self.layers, self.metadata):
            pool.shutdown(wait=False, cancel_futures=True)
        for pool in (self.registries, self.images, self.layers, self.metadata):
            pool.shutdown(wait=True, cancel_futures=True)
        if self.parsers:
            self.parsers.shutdown(wait=True, cancel_futures=True)

    def layer(self, registry: Registry, repository: str, descriptor: dict[str, object],
              limits: Limits) -> Future[Layer]:
        self.check()
        digest = digest_value(descriptor.get("digest"))
        size = descriptor.get("size")
        media = string_value(descriptor.get("mediaType"), "layer mediaType")
        if type(size) is not int or size < 0 or size > limits.layer:
            raise ScanError("INVALID_OR_EXCESSIVE_LAYER_SIZE")
        key = digest, size, media
        pending_key = id(registry), repository, key

        def existing() -> Future[Layer] | None:
            if key in self.cache:
                value, _ = self.cache[key]
                self.cache.move_to_end(key)
                ready: Future[Layer] = Future()
                ready.set_result(value)
                return ready
            return self.inflight.get(pending_key)

        with self.guard:
            found = existing()
            if found:
                return found
        self.layer_slots.acquire()
        with self.guard:
            try:
                self.check()
            except ScanError:
                self.layer_slots.release()
                raise
            found = existing()
            if found:
                self.layer_slots.release()
                return found

            def load() -> Layer:
                try:
                    self.check()
                    with tempfile.TemporaryDirectory(prefix="acr-layer-") as directory:
                        path = str(Path(directory) / "layer")
                        with open(path, "wb") as file:
                            registry.blob(repository, descriptor, file, limits.layer)
                        with self.parse_slots:
                            if self.parsers and size >= 8 * 1024 * 1024:
                                try:
                                    return self.parsers.submit(
                                        parse_layer_file, path, digest, limits.file, limits.unpacked,
                                    ).result()
                                except (BrokenProcessPool, OSError) as exc:
                                    raise ScanError(
                                        f"CPU_PARSER_FAILED: {type(exc).__name__}; try --thread-parsers",
                                    ) from exc
                            with open(path, "rb") as file:
                                return scan_layer(file, digest, limits.file, limits.unpacked, self.stop)
                except AccessDeniedError as exc:
                    error = exc.at(Repository=repository, LayerDigest=digest)
                    self.deny(error)
                    raise error

            try:
                future = self.layers.submit(load)
            except RuntimeError:
                self.layer_slots.release()
                raise
            self.inflight[pending_key] = future

            def completed(done: Future[Layer]) -> None:
                with self.guard:
                    self.inflight.pop(pending_key, None)
                    if not done.cancelled() and done.exception() is None:
                        value = done.result()
                        # Conservative metadata budget; it excludes active parsers and image state.
                        weight = sum(512 + 4 * (len(c.path) + len(c.target)
                                     + (len(c.component.note) if c.component else 0))
                                     for c in value.changes)
                        weight += sum(256 + 4 * len(p) for p in (*value.whiteouts, *value.opaque))
                        if weight <= self.cache_limit:
                            if key in self.cache:
                                self.cache_bytes -= self.cache.pop(key)[1]
                            self.cache[key] = value, weight
                            self.cache_bytes += weight
                            while self.cache_bytes > self.cache_limit:
                                _, (_, removed) = self.cache.popitem(last=False)
                                self.cache_bytes -= removed
                self.layer_slots.release()

            future.add_done_callback(completed)
            return future


def analyze(registry: Registry, target: Target, cache: dict[str, Layer], limits: Limits,
            parallel: Parallelism | None = None) -> Analysis:
    manifest = target.manifest
    artifact_type = manifest.get("artifactType")
    if artifact_type is not None and not isinstance(artifact_type, str):
        raise ScanError("INVALID_ARTIFACT_TYPE")
    if string_value(manifest.get("mediaType"), "manifest mediaType") not in IMAGE_TYPES:
        raise ScanError("UNSUPPORTED_MANIFEST_MEDIA_TYPE")
    config = object_value(manifest.get("config"), "image config descriptor")
    if string_value(config.get("mediaType"), "config mediaType") not in CONFIG_TYPES:
        return Analysis("NON_IMAGE_ARTIFACT")
    output = io.BytesIO()
    registry.blob(target.repository, config, output, 4 * 1024 * 1024)
    settings = json_object(output.getvalue(), "image config")
    os_name = string_value(settings.get("os"), "image OS")
    architecture = string_value(settings.get("architecture"), "image architecture")
    variant = settings.get("variant", "")
    if not isinstance(variant, str):
        raise ScanError("INVALID_IMAGE_VARIANT")
    descriptors = [
        object_value(value, "layer descriptor")
        for value in list_value(manifest.get("layers"), "image layers")
    ]
    if (os_name == "unknown" and architecture == "unknown" and descriptors
            and all(isinstance(descriptor.get("mediaType"), str)
                    and descriptor.get("mediaType") in ATTESTATION_TYPES for descriptor in descriptors)):
        return Analysis("NON_IMAGE_ARTIFACT", os_name, architecture, variant)
    state: dict[str, Component] = {}
    links: set[str] = set()
    for descriptor in descriptors:
        if string_value(descriptor.get("mediaType"), "layer mediaType") not in LAYER_TYPES:
            raise ScanError("UNSUPPORTED_LAYER_MEDIA_TYPE")

    pending: deque[Future[Layer]] = deque()
    if parallel:
        for descriptor in descriptors[:2]:
            pending.append(parallel.layer(registry, target.repository, descriptor, limits))
    for index, descriptor in enumerate(descriptors):
        digest = digest_value(descriptor.get("digest"))
        if parallel:
            value = pending.popleft().result()
            if index + 2 < len(descriptors):
                pending.append(parallel.layer(registry, target.repository, descriptors[index + 2], limits))
        elif digest not in cache:
            with tempfile.TemporaryFile() as file:
                registry.blob(target.repository, descriptor, file, limits.layer)
                file.seek(0)
                cache[digest] = scan_layer(file, digest, limits.file, limits.unpacked)
            value = cache[digest]
        else:
            value = cache[digest]
        apply_layer(state, links, value)
    components = sorted(state.values(), key=lambda component: component.path)
    raw_config = settings.get("config")
    config_values = {} if raw_config is None else object_value(raw_config, "image runtime config")
    raw_environment = config_values.get("Env")
    environment = [] if raw_environment is None else raw_environment
    if not isinstance(environment, list) or not all(isinstance(value, str) for value in environment):
        raise ScanError("INVALID_IMAGE_ENVIRONMENT")
    php_environment = [value for value in environment if value.startswith("PHP_VERSION=")]
    node_environment = [value for value in environment if value.startswith("NODE_VERSION=")]
    has_php = any(c.family == "PHP" for c in components)
    has_node = any(c.family == "NODE" for c in components)
    if not has_php and php_environment:
        components.append(Component(
            "(image config)", "", "PHP_VERSION_ENV_ONLY", "",
            "Image metadata is not executable-version proof", "PHP",
        ))
    if not has_node and node_environment:
        components.append(Component(
            "(image config)", "", "NODE_VERSION_ENV_ONLY", "",
            "Image metadata is not executable-version proof", "NODE",
        ))
    assessments = [assess_version(component.version, component.family) for component in components]
    complete = not any(component.evidence == "SIZE_LIMIT" for component in components)
    if not complete:
        status = "INCOMPLETE"
    elif "AFFECTED_UPSTREAM_RANGE" in assessments:
        status = "AFFECTED_VERSION_DETECTED"
    elif "UNKNOWN" in assessments:
        status = "UNKNOWN"
    elif components:
        status = "FIXED_VERSION_DETECTED"
    else:
        status = "NO_RUNTIME_SIGNATURE_FOUND"
    return Analysis(status, os_name, architecture, variant, components, complete)


def csv_cell(value: object) -> str:
    text = str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


class Report:
    def __init__(self, stream: TextIO, registry: str, *, header: bool = True,
                 context: dict[str, str] | None = None, summary_type: str = "SUMMARY",
                 lock: threading.RLock | None = None) -> None:
        self.stream = stream
        self.registry = registry
        self.context = context or {}
        self.summary_type = summary_type
        self.lock = lock or threading.RLock()
        self.writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        if header:
            self.writer.writeheader()

    def write(self, record_type: str, **values: object) -> None:
        row = {
            "RecordType": record_type, "Registry": self.registry,
            "ScannedAtUtc": datetime.now(timezone.utc).isoformat(), **self.context,
            **values,
        }
        with self.lock:
            self.writer.writerow({key: csv_cell(value) for key, value in row.items()})
            self.stream.flush()

    def issue(self, issue: Issue, status: str = "ERROR") -> None:
        self.write(
            "INVENTORY_ERROR", Repository=issue.repository, Digest=issue.digest,
            ImageStatus=status, ReviewRequired="TRUE", CoverageComplete="FALSE",
            Notes=issue.message,
        )

    def image(self, target: Target, result: Analysis) -> None:
        common: dict[str, object] = {
            "Repository": target.repository, "Digest": target.digest,
            "Tags": json.dumps(sorted(target.tags), ensure_ascii=False),
            "IndexDigests": json.dumps(sorted(target.indexes)),
            "IndexTags": json.dumps(sorted(target.index_tags), ensure_ascii=False),
            "OS": result.os, "Architecture": result.architecture, "Variant": result.variant,
            "ImageStatus": result.status, "CoverageComplete": str(result.complete).upper(),
            "ReviewRequired": "TRUE", "PatchVerification": "NOT_VERIFIED",
        }
        if not result.components:
            self.write("ARTIFACT" if result.status == "NON_IMAGE_ARTIFACT" else "IMAGE",
                       **common, Notes=result.notes or
                       "No safety verdict: absence of a signature is not proof of absence")
        for component in result.components:
            assessment = assess_version(component.version, component.family)
            cve_columns: dict[str, str] = {}
            if component.family == "PHP":
                for cve in PHP_CVE_IDS:
                    cve_columns[cve] = assessment
                for cve in NODE_CVE_IDS:
                    cve_columns[cve] = "NOT_APPLICABLE"
                php_ver, node_ver = component.version, ""
            elif component.family == "NODE":
                for cve in PHP_CVE_IDS:
                    cve_columns[cve] = "NOT_APPLICABLE"
                for cve in NODE_CVE_IDS:
                    cve_columns[cve] = assessment
                php_ver, node_ver = "", component.version
            else:
                for cve in CVE_IDS:
                    cve_columns[cve] = "UNKNOWN"
                php_ver, node_ver = "", ""
            self.write(
                "IMAGE", **common, RuntimeFamily=component.family,
                ComponentPath=component.path, RuntimeVersion=component.version,
                PHPVersion=php_ver, NodeVersion=node_ver,
                Evidence=component.evidence, LayerDigest=component.layer,
                **cve_columns,
                Notes=component.note or "Confirm vendor backports and trusted build provenance",
            )


def scan(registry: Registry, report: Report, limits: Limits, parallel: Parallelism | None = None) -> int:
    snapshot = inventory(registry, parallel)
    for issue in snapshot.issues:
        report.issue(issue)
    counts: Counter[str] = Counter()
    cache: dict[str, Layer] = {}
    def inspect(target: Target) -> tuple[Target, Analysis]:
        try:
            if parallel:
                parallel.check()
            result = analyze(registry, target, cache, limits, parallel)
        except AccessDeniedError as exc:
            error = exc.at(Repository=target.repository, Digest=target.digest)
            if parallel:
                parallel.deny(error)
            raise error
        except ScanError as exc:
            result = Analysis("ERROR", complete=False, notes=str(exc))
        return target, result

    for number, (target, result) in enumerate(bounded_map(
        parallel.images if parallel else None, inspect, snapshot.targets.values(),
        parallel.workers * 2 if parallel else 1,
        check=parallel.check if parallel else None,
    ), 1):
        print(f"[{number}/{len(snapshot.targets)}] {target.repository}@{target.digest}", file=sys.stderr)
        counts[result.status] += 1
        report.image(target, result)
    after, after_issues = catalog(registry, parallel)
    for issue in after_issues:
        report.issue(issue)
    current = {
        (repository, reference.digest)
        for repository, references in after.items() for reference in references
    }
    changed = current != snapshot.listed
    if changed:
        for repository, digest in sorted(current - snapshot.listed):
            report.issue(Issue(repository, digest, "Image appeared after initial inventory"), "NOT_SCANNED")
        for repository, digest in sorted(snapshot.listed - current):
            report.issue(Issue(repository, digest, "Manifest disappeared during scanning"), "INVENTORY_CHANGED")
    inventory_complete = not snapshot.issues and not after_issues and not changed
    operational_error = (
        not inventory_complete or counts["ERROR"] > 0 or counts["INCOMPLETE"] > 0
    )
    exit_code = 2 if operational_error else (
        1 if counts["AFFECTED_VERSION_DETECTED"] else (3 if counts["UNKNOWN"] else 0)
    )
    report.write(
        report.summary_type, ImageStatus="INCOMPLETE" if operational_error else "SCAN_FINISHED",
        InventoryComplete=str(inventory_complete).upper(),
        CoverageComplete=str(not operational_error).upper(), ReviewRequired="TRUE",
        Notes=json.dumps({
            "images_and_artifacts": sum(counts.values()), "status_counts": dict(counts),
            "inventory_changed": changed, "exit_code": exit_code,
            "scope": "visible registry catalog; static native PHP/Node.js signatures; no patch attestation",
        }, sort_keys=True),
    )
    return exit_code


def management_group_id(value: str) -> str:
    prefix = "/providers/Microsoft.Management/managementGroups/"
    if value.lower().startswith(prefix.lower()):
        value = value[len(prefix):]
    if not re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", value) or value in (".", ".."):
        raise argparse.ArgumentTypeError("Use a management group ID or its full ARM resource ID")
    return value


@dataclass(frozen=True)
class ScopedRegistry:
    subscription: str
    subscription_name: str
    name: str
    resource_id: str


@dataclass
class ScopeInventory:
    subscriptions: dict[str, str] = field(default_factory=dict)
    registries: dict[str, ScopedRegistry] = field(default_factory=dict)
    issues: list[tuple[str, str]] = field(default_factory=list)


def arm_pages(url: str, subscription: str | None = None,
              stop: threading.Event | None = None,
              auth: AzureCliAuth | None = None) -> Iterator[dict[str, object]]:
    origin = urllib.parse.urlsplit(url)
    seen: set[str] = set()
    while url:
        if stop and stop.is_set():
            raise ScanError("CANCELLED")
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.netloc != origin.netloc
                or parsed.path != origin.path or parsed.fragment
                or parsed.username or parsed.password or url in seen):
            raise ScanError("INVALID_OR_REPEATED_ARM_NEXT_LINK")
        seen.add(url)
        arguments = ["rest", "--method", "get", "--url", url]
        if subscription:
            arguments.extend(["--subscription", subscription])
        page = auth.arm_json(url) if auth else object_value(run_az(arguments), "ARM page")
        for item in list_value(page.get("value"), "ARM page value"):
            yield object_value(item, "ARM resource")
        next_link = page.get("nextLink")
        url = (urllib.parse.urljoin(url, string_value(next_link, "ARM nextLink"))
               if next_link is not None else "")


def discover_scope(group: str, arm: str, parallel: Parallelism | None = None,
                   auth: AzureCliAuth | None = None) -> ScopeInventory:
    result = ScopeInventory()
    url = (f"{arm}/providers/Microsoft.Management/managementGroups/"
           f"{urllib.parse.quote(group, safe='')}/descendants?api-version=2020-05-01")
    try:
        for item in arm_pages(url, stop=parallel.stop if parallel else None, auth=auth):
            resource_id = string_value(item.get("id"), "descendant id")
            if not resource_id.lower().startswith("/subscriptions/"):
                if string_value(item.get("type"), "descendant type").lower() != "microsoft.management/managementgroups":
                    raise ScanError("UNEXPECTED_MANAGEMENT_GROUP_DESCENDANT")
                continue
            match = re.fullmatch(
                r"/subscriptions/([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})",
                resource_id,
            )
            if not match:
                raise ScanError("INVALID_DESCENDANT_SUBSCRIPTION_ID")
            subscription = match[1].lower()
            properties = object_value(item.get("properties"), "subscription properties")
            result.subscriptions[subscription] = string_value(
                properties.get("displayName"), "subscription display name",
            )
    except AccessDeniedError as exc:
        error = exc.at(ManagementGroup=group)
        if parallel:
            parallel.deny(error)
        raise error
    except ScanError as exc:
        result.issues.append(("", f"MANAGEMENT_GROUP_DISCOVERY_FAILED: {exc}"))
    def read_subscription(item: tuple[str, str]) -> tuple[list[ScopedRegistry], tuple[str, str] | None]:
        subscription, name = item
        entries: list[ScopedRegistry] = []
        issue = None
        prefix = f"/subscriptions/{subscription}/providers/Microsoft.ContainerRegistry/registries"
        try:
            if parallel:
                parallel.check()
            for item in arm_pages(f"{arm}{prefix}?api-version=2023-07-01", subscription,
                                  parallel.stop if parallel else None, auth):
                resource_id = string_value(item.get("id"), "registry id")
                expected = re.fullmatch(
                    rf"/subscriptions/{re.escape(subscription)}/resourceGroups/[^/]+"
                    r"/providers/Microsoft.ContainerRegistry/registries/([A-Za-z0-9]{5,50})",
                    resource_id, re.IGNORECASE,
                )
                if not expected or item.get("name") != expected[1]:
                    raise ScanError("UNEXPECTED_REGISTRY_RESOURCE_ID")
                entries.append(ScopedRegistry(subscription, name, expected[1], resource_id))
        except AccessDeniedError as exc:
            error = exc.at(ManagementGroup=group, SubscriptionId=subscription)
            if parallel:
                parallel.deny(error)
            raise error
        except ScanError as exc:
            issue = subscription, f"REGISTRY_DISCOVERY_FAILED: {exc}"
        return entries, issue

    for entries, issue in bounded_map(parallel.metadata if parallel else None,
                                      read_subscription, result.subscriptions.items(),
                                      check=parallel.check if parallel else None):
        for entry in entries:
            result.registries[entry.resource_id.lower()] = entry
        if issue:
            result.issues.append(issue)
    return result


def scan_management_group(group: str, report: Report, limits: Limits, timeout: int,
                          parallel: Parallelism | None = None, auth: AzureCliAuth | None = None) -> int:
    if auth:
        arm = auth.arm
    else:
        endpoints = object_value(
            object_value(run_az(["cloud", "show"]), "Azure cloud").get("endpoints"), "cloud endpoints",
        )
        arm = string_value(endpoints.get("resourceManager"), "ARM endpoint").rstrip("/")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+", arm):
        raise ScanError("INVALID_ARM_ENDPOINT")
    before = discover_scope(group, arm, parallel, auth)
    codes: list[int] = []

    def discovery_errors(snapshot: ScopeInventory) -> None:
        for subscription, message in snapshot.issues:
            report.write("SCOPE_ERROR", SubscriptionId=subscription, ImageStatus="ERROR",
                         InventoryComplete="FALSE", CoverageComplete="FALSE",
                         ReviewRequired="TRUE", Notes=message)
            codes.append(2)

    discovery_errors(before)
    failed_subscriptions = {subscription for subscription, _ in before.issues}
    for subscription, name in before.subscriptions.items():
        report.write("SUBSCRIPTION", SubscriptionId=subscription, SubscriptionName=name,
                     ImageStatus="DISCOVERY_ERROR" if subscription in failed_subscriptions else "DISCOVERED",
                     Notes=json.dumps({"registries_discovered": sum(
                         entry.subscription == subscription for entry in before.registries.values()
                     )}))
    def inspect_registry(entry: ScopedRegistry) -> int:
        child = Report(report.stream, entry.name, header=False, summary_type="REGISTRY_SUMMARY",
                       context={"ManagementGroup": group, "SubscriptionId": entry.subscription,
                                "SubscriptionName": entry.subscription_name, "RegistryId": entry.resource_id},
                       lock=report.lock)
        print(f"Registry: {entry.subscription}/{entry.name}", file=sys.stderr)
        try:
            if parallel:
                parallel.check()
            registry = (AzureRegistry(entry.name, timeout, subscription=entry.subscription,
                                      auth=auth, resource_id=entry.resource_id,
                                      stop=parallel.stop if parallel else None)
                        if auth else AzureRegistry(entry.name, timeout, subscription=entry.subscription,
                                                   stop=parallel.stop if parallel else None))
            if parallel:
                registry.stop = parallel.stop
            return scan(registry, child, limits, parallel)
        except AccessDeniedError as exc:
            error = exc.at(ManagementGroup=group, Registry=entry.name,
                           SubscriptionId=entry.subscription, RegistryId=entry.resource_id)
            if parallel:
                parallel.deny(error)
            raise error
        except ScanError as exc:
            child.issue(Issue("", "", str(exc)))
            child.write("REGISTRY_SUMMARY", ImageStatus="INCOMPLETE", InventoryComplete="FALSE",
                        CoverageComplete="FALSE", ReviewRequired="TRUE", Notes=str(exc))
            return 2
    codes.extend(bounded_map(parallel.registries if parallel else None,
                             inspect_registry, before.registries.values(), 8,
                             check=parallel.check if parallel else None))
    after = discover_scope(group, arm, parallel, auth)
    discovery_errors(after)
    changed = (before.subscriptions.keys() != after.subscriptions.keys()
               or before.registries.keys() != after.registries.keys())
    if changed:
        codes.append(2)
        report.write("SCOPE_ERROR", ImageStatus="INVENTORY_CHANGED", InventoryComplete="FALSE",
                     CoverageComplete="FALSE", ReviewRequired="TRUE", Notes=json.dumps({
                         "added_subscriptions": sorted(after.subscriptions.keys() - before.subscriptions.keys()),
                         "removed_subscriptions": sorted(before.subscriptions.keys() - after.subscriptions.keys()),
                         "added_registries_not_scanned": sorted(after.registries.keys() - before.registries.keys()),
                         "removed_registries": sorted(before.registries.keys() - after.registries.keys()),
                     }))
    code = next((value for value in (2, 1, 3) if value in codes), 0)
    report.write("MANAGEMENT_GROUP_SUMMARY",
                 ImageStatus="INCOMPLETE" if code == 2 else "SCAN_FINISHED",
                 InventoryComplete=str(code != 2).upper(),
                 CoverageComplete=str(code != 2).upper(), ReviewRequired="TRUE",
                 Notes=json.dumps({"subscriptions": len(before.subscriptions),
                                   "registries": len(before.registries), "exit_code": code,
                                   "scope": "authorized ARM discovery; not an atomic snapshot; no patch attestation"}))
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--registry", help="Azure registry resource name, not a URL")
    scope.add_argument("--management-group", type=management_group_id,
                       help="Management group ID or ARM ID; scans all descendant subscriptions")
    parser.add_argument("--subscription", help="Subscription ID for --registry; defaults to the current CLI subscription")
    parser.add_argument("--resource-group", help="Registry resource group; permits direct ARM lookup with ACR-scoped Reader")
    parser.add_argument("--auth", choices=("azure-cli",), default="azure-cli",
                        help="Azure CLI az login authentication (default; option kept for compatibility)")
    parser.add_argument("--cloud", choices=tuple(CLOUDS), default="AzureCloud")
    parser.add_argument("--output", type=Path, help="New CSV path; existing files are never overwritten")
    parser.add_argument("--max-layer-mib", type=int, default=1024)
    parser.add_argument("--max-file-mib", type=int, default=256)
    parser.add_argument("--max-unpacked-layer-mib", type=int, default=8192)
    parser.add_argument("--timeout", type=int, default=60, help="HTTPS timeout in seconds")
    parser.add_argument("--workers", type=int, default=8, help="Global image/download concurrency (default: 8)")
    parser.add_argument("--registry-workers", type=int, default=4, help="Concurrent registry coordinators (default: 4)")
    parser.add_argument("--metadata-workers", type=int, default=8, help="Global ARM/manifest/CLI workers (default: 8)")
    parser.add_argument("--parse-workers", type=int, default=2, help="Concurrent memory-heavy layer parsers (default: 2)")
    parser.add_argument("--cache-mib", type=int, default=256, help="Approximate completed layer metadata cache budget")
    parser.add_argument("--serial", action="store_true", help="Disable all concurrency for comparison/troubleshooting")
    parser.add_argument("--thread-parsers", action="store_true",
                        help="Use threads instead of processes for large-layer CPU analysis")
    args = parser.parse_args(argv)
    if args.registry and not re.fullmatch(r"[A-Za-z0-9]{5,50}", args.registry):
        parser.error("--registry must be a 5-50 character alphanumeric ACR resource name")
    if args.management_group and args.subscription:
        parser.error("--subscription is only valid with --registry")
    if args.management_group and args.resource_group:
        parser.error("--resource-group is only valid with --registry")
    if min(args.max_layer_mib, args.max_file_mib, args.max_unpacked_layer_mib, args.timeout) <= 0:
        parser.error("size limits and timeout must be positive")
    if not all(1 <= value <= 64 for value in (
        args.workers, args.registry_workers, args.metadata_workers, args.parse_workers,
    )):
        parser.error("worker counts must be between 1 and 64")
    if args.cache_mib < 0:
        parser.error("--cache-mib must not be negative")
    output = args.output or Path(
        f"{args.management_group or args.registry}-runtime-cves-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.csv"
    )
    limits = Limits(
        args.max_layer_mib * 1024 * 1024, args.max_file_mib * 1024 * 1024,
        args.max_unpacked_layer_mib * 1024 * 1024,
    )
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8-sig", newline="") as stream:
            summary_type = "MANAGEMENT_GROUP_SUMMARY" if args.management_group else "SUMMARY"
            report = Report(stream, args.registry or "", summary_type=summary_type,
                            context={"ManagementGroup": args.management_group or "",
                                     "SubscriptionId": args.subscription or ""})
            try:
                started = time.perf_counter()
                with Parallelism(
                    1 if args.serial else args.workers,
                    1 if args.serial else args.registry_workers,
                    1 if args.serial else args.metadata_workers,
                    1 if args.serial else args.parse_workers, args.cache_mib,
                    not (args.serial or args.thread_parsers),
                ) as parallel:
                    auth = create_auth(args)
                    if auth:
                        auth.stop = parallel.stop
                    if args.management_group:
                        exit_code = scan_management_group(args.management_group, report, limits,
                                                          args.timeout, parallel, auth)
                    else:
                        if auth:
                            subscription = args.subscription or os.environ.get("AZURE_SUBSCRIPTION_ID")
                            resource_id = None
                            if args.resource_group:
                                if not subscription:
                                    account = object_value(run_az(["account", "show"]), "active CLI account")
                                    subscription = string_value(account.get("id"), "active subscription id")
                                resource_id = (f"/subscriptions/{urllib.parse.quote(subscription, safe='')}"
                                               f"/resourceGroups/{urllib.parse.quote(args.resource_group, safe='')}"
                                               f"/providers/Microsoft.ContainerRegistry/registries/{args.registry}")
                            registry = AzureRegistry(args.registry, args.timeout, subscription=subscription,
                                                     auth=auth, resource_id=resource_id, stop=parallel.stop)
                        else:
                            registry = (AzureRegistry(args.registry, args.timeout, subscription=args.subscription,
                                                      stop=parallel.stop)
                                        if args.subscription else AzureRegistry(args.registry, args.timeout,
                                                                               stop=parallel.stop))
                        registry.stop = parallel.stop
                        exit_code = scan(registry, report, limits, parallel)
                print(f"Elapsed: {time.perf_counter() - started:.2f}s", file=sys.stderr)
            except AccessDeniedError as exc:
                report.write("PERMISSION_ERROR", **exc.context, ImageStatus="ACCESS_DENIED",
                             InventoryComplete="FALSE", CoverageComplete="FALSE",
                             ReviewRequired="TRUE", Notes=str(exc))
                report.write(summary_type, ImageStatus="ABORTED_ACCESS_DENIED",
                             InventoryComplete="FALSE", CoverageComplete="FALSE",
                             ReviewRequired="TRUE", Notes=str(exc))
                print(f"Stopped: {exc}", file=sys.stderr, flush=True)
                exit_code = 2
            except ScanError as exc:
                report.issue(Issue("", "", str(exc)))
                report.write(summary_type, ImageStatus="INCOMPLETE", InventoryComplete="FALSE",
                             CoverageComplete="FALSE", ReviewRequired="TRUE", Notes="Exit code: 2")
                print(str(exc), file=sys.stderr)
                exit_code = 2
            except KeyboardInterrupt:
                report.write(summary_type, ImageStatus="INTERRUPTED", InventoryComplete="FALSE",
                             CoverageComplete="FALSE", ReviewRequired="TRUE", Notes="Exit code: 130")
                exit_code = 130
    except OSError as exc:
        print(f"CSV_WRITE_FAILED: {type(exc).__name__}; use a new writable output path", file=sys.stderr)
        return 2
    print(f"CSV: {output.resolve()} | exit code: {exit_code}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
