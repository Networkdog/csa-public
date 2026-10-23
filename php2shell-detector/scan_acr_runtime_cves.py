"""Read-only, dependency-free ACR inventory and PHP2Shell / Node2Shell version-evidence scanner."""

from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import io
import json
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol, TextIO


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
    "RecordType", "Registry", "Repository", "Digest", "Tags", "IndexDigests",
    "IndexTags", "OS", "Architecture", "Variant", "ImageStatus", "RuntimeFamily",
    "ComponentPath", "RuntimeVersion", "PHPVersion", "NodeVersion", "Evidence",
    "LayerDigest", *CVE_IDS, "PatchVerification", "ReviewRequired",
    "CoverageComplete", "InventoryComplete", "Notes", "ScannedAtUtc",
)


class ScanError(Exception):
    pass


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


class AzureRegistry:
    def __init__(self, name: str, timeout: int = 60) -> None:
        self.name = name
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect())
        self.server = ""
        self.refresh_token = ""
        self.tokens: dict[str, tuple[str, float]] = {}
        self._login()

    def _login(self) -> None:
        login = object_value(
            run_az(["acr", "login", "--name", self.name, "--expose-token"]),
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

    def _open(self, request: urllib.request.Request, blob: bool = False) -> http.client.HTTPResponse:
        for _ in range(4):
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

    def _token(self, repository: str) -> str:
        cached = self.tokens.get(repository)
        if cached and cached[1] > time.monotonic():
            return cached[0]
        for attempt in range(2):
            data = urllib.parse.urlencode({
                "grant_type": "refresh_token",
                "service": self.server,
                "scope": f"repository:{repository}:pull",
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
                raise ScanError(f"ACR_TOKEN_HTTP_{status}: verify pull permissions and az login") from None
            token = string_value(json_object(raw, "ACR token").get("access_token"), "access_token")
            self.tokens[repository] = (token, time.monotonic() + 300)
            return token
        raise ScanError("ACR_TOKEN_REFRESH_FAILED")

    def _get(self, repository: str, path: str, blob: bool = False) -> http.client.HTTPResponse:
        for attempt in range(2):
            request = urllib.request.Request(
                f"https://{self.server}{path}",
                headers={
                    "Authorization": f"Bearer {self._token(repository)}",
                    "Accept": ", ".join(sorted(INDEX_TYPES | IMAGE_TYPES)),
                    "User-Agent": "csa-acr-runtime-cves/1.0",
                },
            )
            try:
                return self._open(request, blob=blob)
            except urllib.error.HTTPError as exc:
                status = exc.code
                exc.close()
                if status == 401 and attempt == 0:
                    self._login()
                    continue
                raise ScanError(f"REGISTRY_HTTP_{status}: manifest/blob could not be read") from None
        raise ScanError("REGISTRY_AUTHENTICATION_FAILED")

    def repositories(self) -> Iterator[str]:
        result = list_value(run_az(["acr", "repository", "list", "--name", self.name]), "repositories")
        for item in result:
            yield string_value(item, "repository")

    def manifests(self, repository: str) -> Iterator[ManifestRef]:
        items = list_value(run_az([
            "acr", "manifest", "list-metadata", "--registry", self.name,
            "--name", repository, "--query", "[]",
        ]), "manifests")
        for item in items:
            entry = object_value(item, "manifest metadata")
            tags = entry.get("tags")
            yield ManifestRef(
                digest_value(entry.get("digest")),
                tuple(string_value(tag, "tag") for tag in list_value(tags, "tags"))
                if tags is not None else (),
            )

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


def catalog(registry: Registry) -> tuple[dict[str, list[ManifestRef]], list[Issue]]:
    result: dict[str, list[ManifestRef]] = {}
    issues: list[Issue] = []
    try:
        for repository in registry.repositories():
            try:
                result[repository] = list(registry.manifests(repository))
            except ScanError as exc:
                issues.append(Issue(repository, "", str(exc)))
    except ScanError as exc:
        issues.append(Issue("", "", str(exc)))
    return result, issues


def inventory(registry: Registry) -> Inventory:
    repositories, issues = catalog(registry)
    result = Inventory(issues=issues)
    cache: dict[tuple[str, str], dict[str, object]] = {}

    def expand(repository: str, digest: str, tags: set[str], ancestors: tuple[str, ...],
               inherited_tags: set[str]) -> None:
        if digest in ancestors or len(ancestors) >= 16:
            raise ScanError("MANIFEST_INDEX_CYCLE_OR_DEPTH_LIMIT")
        key = (repository, digest)
        if key not in cache:
            cache[key] = registry.manifest(repository, digest)
        manifest = cache[key]
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
                except ScanError as exc:
                    result.issues.append(Issue(repository, child_digest, str(exc)))
            return
        target = result.targets.setdefault(key, Target(repository, digest, manifest))
        target.tags.update(tags)
        target.indexes.update(ancestors)
        target.index_tags.update(inherited_tags)

    for repository, manifests in repositories.items():
        for reference in manifests:
            result.listed.add((repository, reference.digest))
            try:
                expand(repository, reference.digest, set(reference.tags), (), set())
            except ScanError as exc:
                result.issues.append(Issue(repository, reference.digest, str(exc)))
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


def scan_layer(stream: BinaryIO, digest: str, file_limit: int, unpacked_limit: int) -> Layer:
    whiteouts: list[str] = []
    opaque: list[str] = []
    changes: list[Change] = []
    unpacked = 0
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as archive:
            for member in archive:
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


def analyze(registry: Registry, target: Target, cache: dict[str, Layer], limits: Limits) -> Analysis:
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
        digest = digest_value(descriptor.get("digest"))
        if string_value(descriptor.get("mediaType"), "layer mediaType") not in LAYER_TYPES:
            raise ScanError("UNSUPPORTED_LAYER_MEDIA_TYPE")
        if digest not in cache:
            with tempfile.TemporaryFile() as file:
                registry.blob(target.repository, descriptor, file, limits.layer)
                file.seek(0)
                cache[digest] = scan_layer(file, digest, limits.file, limits.unpacked)
        apply_layer(state, links, cache[digest])
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
    def __init__(self, stream: TextIO, registry: str) -> None:
        self.stream = stream
        self.registry = registry
        self.writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        self.writer.writeheader()

    def write(self, record_type: str, **values: object) -> None:
        row = {
            "RecordType": record_type, "Registry": self.registry,
            "ScannedAtUtc": datetime.now(timezone.utc).isoformat(),
            **values,
        }
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


def scan(registry: Registry, report: Report, limits: Limits) -> int:
    snapshot = inventory(registry)
    for issue in snapshot.issues:
        report.issue(issue)
    counts: Counter[str] = Counter()
    cache: dict[str, Layer] = {}
    for number, target in enumerate(snapshot.targets.values(), 1):
        print(f"[{number}/{len(snapshot.targets)}] {target.repository}@{target.digest}", file=sys.stderr)
        try:
            result = analyze(registry, target, cache, limits)
        except ScanError as exc:
            result = Analysis("ERROR", complete=False, notes=str(exc))
        counts[result.status] += 1
        report.image(target, result)
    after, after_issues = catalog(registry)
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
        "SUMMARY", ImageStatus="INCOMPLETE" if operational_error else "SCAN_FINISHED",
        InventoryComplete=str(inventory_complete).upper(),
        CoverageComplete=str(not operational_error).upper(), ReviewRequired="TRUE",
        Notes=json.dumps({
            "images_and_artifacts": sum(counts.values()), "status_counts": dict(counts),
            "inventory_changed": changed, "exit_code": exit_code,
            "scope": "visible registry catalog; static native PHP/Node.js signatures; no patch attestation",
        }, sort_keys=True),
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", required=True, help="Azure registry resource name, not a URL")
    parser.add_argument("--output", type=Path, help="New CSV path; existing files are never overwritten")
    parser.add_argument("--max-layer-mib", type=int, default=1024)
    parser.add_argument("--max-file-mib", type=int, default=256)
    parser.add_argument("--max-unpacked-layer-mib", type=int, default=8192)
    parser.add_argument("--timeout", type=int, default=60, help="HTTPS timeout in seconds")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9]{5,50}", args.registry):
        parser.error("--registry must be a 5-50 character alphanumeric ACR resource name")
    if min(args.max_layer_mib, args.max_file_mib, args.max_unpacked_layer_mib, args.timeout) <= 0:
        parser.error("size limits and timeout must be positive")
    output = args.output or Path(
        f"{args.registry}-runtime-cves-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.csv"
    )
    limits = Limits(
        args.max_layer_mib * 1024 * 1024, args.max_file_mib * 1024 * 1024,
        args.max_unpacked_layer_mib * 1024 * 1024,
    )
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8-sig", newline="") as stream:
            report = Report(stream, args.registry)
            try:
                registry = AzureRegistry(args.registry, args.timeout)
                exit_code = scan(registry, report, limits)
            except ScanError as exc:
                report.issue(Issue("", "", str(exc)))
                report.write("SUMMARY", ImageStatus="INCOMPLETE", InventoryComplete="FALSE",
                             CoverageComplete="FALSE", ReviewRequired="TRUE", Notes="Exit code: 2")
                print(str(exc), file=sys.stderr)
                exit_code = 2
            except KeyboardInterrupt:
                report.write("SUMMARY", ImageStatus="INTERRUPTED", InventoryComplete="FALSE",
                             CoverageComplete="FALSE", ReviewRequired="TRUE", Notes="Exit code: 130")
                exit_code = 130
    except OSError as exc:
        print(f"CSV_WRITE_FAILED: {type(exc).__name__}; use a new writable output path", file=sys.stderr)
        return 2
    print(f"CSV: {output.resolve()} | exit code: {exit_code}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
