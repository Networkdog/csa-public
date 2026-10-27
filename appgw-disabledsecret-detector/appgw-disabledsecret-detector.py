#!/usr/bin/env python3
"""Export Application Gateway listeners and ARM-only Key Vault Secret state."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

LOG = logging.getLogger("appgw-keyvault-audit")
ARG_API = "2022-10-01"
VAULT_API = "2026-05-15"
GATEWAY_QUERY = """
Resources
| where type =~ 'microsoft.network/applicationgateways'
| project id, name, subscriptionId, resourceGroup, location,
    listeners=properties.httpListeners, certificates=properties.sslCertificates
| order by id asc
"""
VAULT_QUERY = """
Resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, subscriptionId, resourceGroup, vaultUri=tostring(properties.vaultUri)
| order by id asc
"""
FIELDS = [
    "inventory_time_utc", "subscription_id", "resource_group", "appgw_name",
    "appgw_id", "location", "listener_name", "listener_protocol", "host_names",
    "ssl_certificate_name", "configured_secret_uri", "configured_secret_version",
    "key_vault_name", "key_vault_id", "secret_name", "arm_secret_uri_with_version",
    "arm_secret_enabled", "reference_state", "lookup_time_utc", "error",
]
KNOWN_STATES = {"ENABLED", "DISABLED", "NOT_KEY_VAULT", "NO_SSL_CERTIFICATE"}


class ScanError(Exception):
    """A failed or incomplete inventory or CLI request."""


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScanError(f"{label} must be a JSON object")
    return value


def array_value(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ScanError(f"{label} must be a JSON array")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AzureCli:
    def __init__(self) -> None:
        executable = shutil.which("az")
        if not executable:
            raise ScanError("Azure CLI (az) is required. Run this in Azure Cloud Shell.")
        # Avoid cmd.exe metacharacter/quoting behavior with the Windows CLI shim.
        bundled_python = Path(executable).parent.parent / "python.exe"
        self.command = (
            [str(bundled_python), "-IBm", "azure.cli"]
            if sys.platform == "win32" and bundled_python.is_file()
            else [executable]
        )

    def json(self, arguments: list[str]) -> Any:
        for attempt in range(3):
            try:
                result = subprocess.run(
                    self.command + arguments + ["--only-show-errors", "--output", "json"],
                    capture_output=True, text=True, encoding="utf-8", timeout=180,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ScanError("Azure CLI request timed out after 180 seconds") from exc
            if result.returncode == 0:
                if result.stderr.strip():
                    LOG.warning("%s", result.stderr.strip())
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    raise ScanError("Azure CLI returned invalid or empty JSON") from exc
            message = result.stderr.strip() or "Azure CLI failed without an error message"
            transient = re.search(
                r"TooManyRequests|Throttl|ServiceUnavailable|InternalServerError|"
                r"BadGateway|GatewayTimeout|\b(?:429|500|502|503|504)\b",
                message, re.IGNORECASE,
            )
            if not transient or attempt == 2:
                raise ScanError(message)
            LOG.warning("Transient ARM/CLI error; retrying in %s seconds", 2 ** (attempt + 1))
            time.sleep(2 ** (attempt + 1))
        raise ScanError("Azure CLI retry budget exhausted")


class ArmClient:
    def __init__(self, cli: AzureCli, endpoint: str) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ScanError("The Azure cloud Resource Manager endpoint is invalid")
        self.cli = cli
        self.endpoint = endpoint.rstrip("/")

    def request(self, method: str, resource_path: str, body: dict[str, Any] | None = None,
                projection: str | None = None) -> dict[str, Any]:
        if not resource_path.startswith("/") or resource_path.startswith("//"):
            raise ScanError("Only absolute ARM resource paths are accepted")
        arguments = ["rest", "--method", method, "--url", self.endpoint + resource_path]
        if projection:
            arguments += ["--query", projection]
        if body is None:
            return object_value(self.cli.json(arguments), "ARM response")
        # @file avoids shell quoting limits; the body contains inventory KQL, not secrets.
        with tempfile.TemporaryDirectory(prefix="appgw-arg-") as directory:
            path = Path(directory) / "query.json"
            path.write_text(json.dumps(body), encoding="utf-8")
            return object_value(self.cli.json(arguments + ["--body", f"@{path}"]), "ARG response")

    def check_management_group_scope(self, management_group: str) -> int:
        page = self.request(
            "post", f"/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}",
            {
                "managementGroups": [management_group],
                "query": "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | summarize subscriptionCount=count()",
                "options": {"resultFormat": "objectArray"},
            },
        )
        data = array_value(page.get("data"), "Management group subscription count")
        count = data[0].get("subscriptionCount") if len(data) == 1 and isinstance(data[0], dict) else None
        if type(count) is not int or count < 0:
            raise ScanError("ARG did not return a valid management group subscription count")
        if count >= 10000:
            raise ScanError(
                "Management group scope reached ARG's 10,000-subscription boundary. "
                "Run separately for smaller child management groups to avoid an incomplete report."
            )
        return count

    def graph(self, query: str, subscriptions: list[str] | None = None,
              management_group: str | None = None) -> list[dict[str, Any]]:
        if bool(subscriptions) == bool(management_group):
            raise ScanError("Specify exactly one ARG scope: subscriptions or a management group")
        scopes: list[dict[str, Any]]
        if management_group:
            scopes = [{"managementGroups": [management_group]}]
        else:
            subscriptions = subscriptions or []
            scopes = [
                {"subscriptions": subscriptions[start:start + 100]}
                for start in range(0, len(subscriptions), 100)
            ]
        inventory: dict[str, dict[str, Any]] = {}
        for scope in scopes:
            token = ""
            seen: set[str] = set()
            batch_count = 0
            while True:
                options: dict[str, Any] = {"$top": 1000, "resultFormat": "objectArray"}
                if token:
                    options["$skipToken"] = token
                page = self.request(
                    "post", f"/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}",
                    {**scope, "query": query, "options": options},
                )
                data = array_value(page.get("data"), "ARG data")
                if page.get("count") != len(data):
                    raise ScanError("ARG count does not match the returned rows")
                total = page.get("totalRecords")
                if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                    raise ScanError("ARG did not return a valid totalRecords")
                for item in data:
                    row = object_value(item, "ARG resource")
                    resource_id = row.get("id")
                    if not isinstance(resource_id, str) or not resource_id:
                        raise ScanError("ARG resource is missing its id")
                    key = resource_id.lower()
                    if key in inventory:
                        raise ScanError("ARG repeated a resource; inventory changed during pagination")
                    inventory[key] = row
                batch_count += len(data)
                token = page.get("$skipToken") or ""
                if not isinstance(token, str):
                    raise ScanError("ARG returned an invalid continuation token")
                if not token:
                    if batch_count != total or str(page.get("resultTruncated")).lower() == "true":
                        raise ScanError("ARG inventory was truncated without usable continuation")
                    break
                if token in seen or not data:
                    raise ScanError("ARG pagination repeated a token or returned an empty page")
                seen.add(token)
        return list(inventory.values())


def management_group_id(value: str) -> str:
    prefix = "/providers/Microsoft.Management/managementGroups/"
    name = value[len(prefix):] if value.lower().startswith(prefix.lower()) else value
    if not re.fullmatch(r"[A-Za-z0-9_.()-]{1,90}", name):
        raise argparse.ArgumentTypeError("Use a management group ID (not display name) or its full ARM resource ID")
    return name


def subscription_scope(cli: AzureCli, requested: list[str] | None) -> list[str]:
    current = object_value(cli.json(["account", "show"]), "Azure account")
    tenant_id = current.get("tenantId")
    if not tenant_id:
        raise ScanError("Azure account has no tenantId; run az login or select a Cloud Shell tenant")
    accounts = array_value(cli.json(["account", "list", "--all"]), "Azure accounts")
    available = {
        str(a["id"]).lower(): str(a["id"])
        for a in accounts if isinstance(a, dict) and a.get("id")
        and a.get("tenantId") == tenant_id and a.get("state") == "Enabled"
    }
    if requested:
        ids = list(dict.fromkeys(str(uuid.UUID(s)).lower() for s in requested))
        missing = [s for s in ids if s not in available]
        if missing:
            raise ScanError(f"Subscriptions are not Enabled in the current tenant/CLI context: {missing}")
        return [available[s] for s in ids]
    if not available:
        raise ScanError("No Enabled subscriptions found in the current Azure CLI tenant")
    return sorted(available.values())


def secret_reference(uri: str, vault_suffix: str) -> tuple[str, str, str]:
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.port not in (None, 443) or parsed.query or parsed.fragment
        or not parsed.hostname.lower().endswith(vault_suffix.lower())
    ):
        raise ScanError("Not a valid HTTPS Secret URI for the active Azure cloud")
    match = re.fullmatch(r"/secrets/([A-Za-z0-9-]+)(?:/([A-Za-z0-9]+))?/?", parsed.path)
    if not match:
        raise ScanError("Expected /secrets/<name>[/<version>]")
    return parsed.hostname.lower(), match[1], match[2] or ""


def vault_index(vaults: list[dict[str, Any]], suffix: str) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for vault in vaults:
        name = vault.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]+", name):
            raise ScanError("Vault inventory contains an invalid vault name")
        uri = vault.get("vaultUri") or f"https://{name}{suffix}/"
        host = urlsplit(uri).hostname
        if not host or not host.endswith(suffix.lower()):
            raise ScanError(f"Invalid vaultUri in inventory for {name}")
        index.setdefault(host.lower(), []).append(vault)
    return index


def scan_listeners(
    gateways: list[dict[str, Any]], vaults: list[dict[str, Any]],
    arm: ArmClient, suffix: str,
) -> list[dict[str, Any]]:
    index = vault_index(vaults, suffix)
    cache: dict[str, tuple[dict[str, Any] | None, str, str]] = {}
    rows: list[dict[str, Any]] = []
    inventory_time = utc_now()
    for gateway in gateways:
        listeners = array_value(
            gateway["listeners"] if gateway.get("listeners") is not None else [], "Gateway listeners"
        )
        certificates = array_value(
            gateway["certificates"] if gateway.get("certificates") is not None else [], "Gateway certificates"
        )
        cert_by_id: dict[str, dict[str, Any]] = {}
        for value in certificates:
            certificate = object_value(value, "SSL certificate")
            cert_id = str(certificate.get("id", "")).lower()
            if not cert_id or cert_id in cert_by_id:
                raise ScanError("Gateway SSL certificate id is missing or duplicated")
            cert_by_id[cert_id] = certificate
        for value in listeners:
            listener = object_value(value, "Listener")
            props = object_value(listener.get("properties"), "Listener properties")
            row: dict[str, Any] = dict.fromkeys(FIELDS, "")
            row.update(
                inventory_time_utc=inventory_time, subscription_id=gateway.get("subscriptionId", ""),
                resource_group=gateway.get("resourceGroup", ""), appgw_name=gateway.get("name", ""),
                appgw_id=gateway["id"], location=gateway.get("location", ""),
                listener_name=listener.get("name", ""), listener_protocol=props.get("protocol", ""),
                host_names=json.dumps(props.get("hostNames") or [props.get("hostName") or ""], ensure_ascii=False),
            )
            ssl = props.get("sslCertificate")
            if not ssl:
                row["reference_state"] = "NO_SSL_CERTIFICATE"
            else:
                ssl_id = str(object_value(ssl, "Listener SSL reference").get("id", "")).lower()
                certificate = cert_by_id.get(ssl_id)
                if certificate is None:
                    row.update(reference_state="CERTIFICATE_NOT_FOUND", error="Listener SSL id not in ARG certificate inventory")
                else:
                    row["ssl_certificate_name"] = certificate.get("name", "")
                    cert_props = object_value(certificate.get("properties"), "SSL certificate properties")
                    uri = cert_props.get("keyVaultSecretId")
                    if not uri:
                        row["reference_state"] = "NOT_KEY_VAULT"
                    else:
                        row["configured_secret_uri"] = uri
                        try:
                            host, name, version = secret_reference(uri, suffix)
                            row.update(secret_name=name, configured_secret_version=version)
                            matches = index.get(host, [])
                            if len(matches) != 1:
                                row.update(
                                    reference_state="VAULT_NOT_FOUND" if not matches else "AMBIGUOUS_VAULT",
                                    error="Vault hostname is not uniquely visible in the selected ARG scope",
                                )
                            else:
                                vault = matches[0]
                                row.update(key_vault_name=vault["name"], key_vault_id=vault["id"])
                                resource_id = f"{vault['id']}/secrets/{quote(name, safe='')}"
                                if resource_id.lower() not in cache:
                                    checked_at = utc_now()
                                    try:
                                        metadata = arm.request(
                                            "get", f"{resource_id}?api-version={VAULT_API}",
                                            projection="{enabled:properties.attributes.enabled,versionUri:properties.secretUriWithVersion}",
                                        )
                                        cache[resource_id.lower()] = (metadata, checked_at, "")
                                    except ScanError as exc:
                                        cache[resource_id.lower()] = (None, checked_at, str(exc))
                                metadata, checked_at, error = cache[resource_id.lower()]
                                row["lookup_time_utc"] = checked_at
                                if metadata is None:
                                    row.update(reference_state="ARM_LOOKUP_FAILED", error=error)
                                else:
                                    enabled = metadata.get("enabled")
                                    resolved = metadata.get("versionUri")
                                    row["arm_secret_uri_with_version"] = resolved or ""
                                    if type(enabled) is not bool or not isinstance(resolved, str):
                                        raise ScanError("ARM response lacks boolean enabled or versioned Secret URI")
                                    row["arm_secret_enabled"] = str(enabled).lower()
                                    resolved_host, resolved_name, resolved_version = secret_reference(resolved, suffix)
                                    if resolved_host != host or resolved_name.lower() != name.lower() or not resolved_version:
                                        raise ScanError("ARM returned a different Secret or an unversioned URI")
                                    if version and version.lower() != resolved_version.lower():
                                        row.update(
                                            reference_state="VERSION_MISMATCH",
                                            error="ARM returned another version; configured version state is unknown",
                                        )
                                    else:
                                        row["reference_state"] = "ENABLED" if enabled else "DISABLED"
                        except (ScanError, ValueError, TypeError) as exc:
                            row.update(reference_state="INVALID_OR_INCOMPLETE_METADATA", error=str(exc))
            if row["reference_state"] not in KNOWN_STATES:
                LOG.warning("%s / %s: %s: %s", row["appgw_name"], row["listener_name"],
                            row["reference_state"], row["error"])
            rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            # Keep metadata from being interpreted as formulas when opened in Excel.
            safe = {
                key: "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))
                else value for key, value in row.items()
            }
            writer.writerow(safe)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--management-group", type=management_group_id, metavar="MANAGEMENT_GROUP_ID",
                       help="Scan this management group and all descendants using ARG server-side scope; no subscription list required.")
    scope.add_argument("--subscriptions", nargs="+", metavar="SUBSCRIPTION_ID",
                       help="Default without --management-group: all Enabled CLI subscriptions in the current tenant. Include Vault subscriptions too.")
    parser.add_argument("--output", type=Path,
                        help="CSV path. Default: <management-group-id>-<UTC timestamp>.csv; without a management group, appgw-keyvault-<UTC timestamp>.csv.")
    args = parser.parse_args(argv)
    if args.output is None:
        prefix = args.management_group or "appgw-keyvault"
        args.output = Path(f"{prefix}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.csv")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        if args.output.exists():
            raise ScanError(f"Output already exists; choose another path: {args.output}")
        cli = AzureCli()
        subscriptions = None if args.management_group else subscription_scope(cli, args.subscriptions)
        cloud = object_value(cli.json(["cloud", "show"]), "Azure cloud")
        endpoints = object_value(cloud.get("endpoints"), "Cloud endpoints")
        suffixes = object_value(cloud.get("suffixes"), "Cloud suffixes")
        suffix = suffixes.get("keyvaultDns")
        if not isinstance(suffix, str) or not suffix.startswith("."):
            raise ScanError("Active cloud does not define a Key Vault DNS suffix")
        arm = ArmClient(cli, endpoints["resourceManager"])
        if args.management_group:
            count = arm.check_management_group_scope(args.management_group)
            LOG.info("Read-only ARM scan: management group %s including descendants; %s visible subscriptions",
                     args.management_group, count)
        else:
            LOG.info("Read-only ARM scan: %s subscriptions in current tenant", len(subscriptions or []))
        LOG.info("No Vault data-plane calls; ARG returns only resources readable by the signed-in identity")
        gateways = arm.graph(GATEWAY_QUERY, subscriptions, management_group=args.management_group)
        vaults = arm.graph(VAULT_QUERY, subscriptions, management_group=args.management_group)
        rows = scan_listeners(gateways, vaults, arm, suffix)
        write_csv(args.output, rows)
        counts = Counter(row["reference_state"] for row in rows)
        unknown = sum(count for state, count in counts.items() if state not in KNOWN_STATES)
        LOG.info("Gateways=%s, listeners=%s, disabled=%s, unknown=%s; CSV=%s",
                 len(gateways), len(rows), counts["DISABLED"], unknown, args.output)
        LOG.info("States: %s", dict(sorted(counts.items())))
        LOG.warning("ARM Secret API is documented for internal use in ARM deployments. Review support/governance before operational use.")
        return 2 if unknown else 0
    except (ScanError, OSError, ValueError, KeyError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
