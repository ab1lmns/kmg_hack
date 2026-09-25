"""Read-only fixed-schema HTTPS collector for a developer's local backend."""

import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .collectors import CollectorError, classify_snapshot
from .models import Account, Computer, Group, Snapshot
from .infrastructure import empty_infrastructure


MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_INFRASTRUCTURE_BYTES = 32 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise CollectorError("Gateway redirect запрещён")


def collect_gateway_infrastructure(settings):
    """Fetch only the gateway's fixed infrastructure schema, never arbitrary LDAP."""
    url = settings.ad_gateway_url
    parsed = urlsplit(url)
    fallback = empty_infrastructure()
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or not settings.ad_gateway_token:
        return fallback
    request = urllib.request.Request(url + "/v1/infrastructure", headers={
        "Authorization": "Bearer " + settings.ad_gateway_token,
        "Accept": "application/json",
    })
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            if response.headers.get_content_type() != "application/json":
                return fallback
            body = response.read(MAX_INFRASTRUCTURE_BYTES + 1)
        if len(body) > MAX_INFRASTRUCTURE_BYTES:
            return fallback
        payload = json.loads(body)
        if payload.get("schema_version") != 1 or not isinstance(payload.get("infrastructure"), dict):
            return fallback
        data = payload["infrastructure"]
        return data if all(key in data for key in fallback) else fallback
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError, KeyError):
        fallback["diagnostics"]["LDAP_CONNECTION"] = "error"
        return fallback


def collect_gateway(settings) -> Snapshot:
    url = settings.ad_gateway_url
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CollectorError("AD_GATEWAY_URL должен быть HTTPS URL без credentials/query")
    if not settings.ad_gateway_token:
        raise CollectorError("Укажите личный AD_GATEWAY_TOKEN только в локальном backend/.env")
    request = urllib.request.Request(url + "/v1/snapshot", headers={
        "Authorization": "Bearer " + settings.ad_gateway_token,
        "Accept": "application/json",
    })
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    try:
        with opener.open(request, timeout=100) as response:
            if response.headers.get_content_type() != "application/json":
                raise CollectorError("Gateway вернул неверный формат")
            body = response.read(MAX_SNAPSHOT_BYTES + 1)
            if len(body) > MAX_SNAPSHOT_BYTES:
                raise CollectorError("Gateway snapshot слишком большой")
        payload = json.loads(body)
        if payload.get("schema_version") != 1 or not isinstance(payload.get("snapshot"), dict):
            raise CollectorError("Несовместимая версия Gateway snapshot")
        data = payload["snapshot"]
        if len(data.get("accounts", [])) > 10000 or len(data.get("groups", [])) > 20000 or len(data.get("auth_events", [])) > 5000:
            raise CollectorError("Gateway snapshot превышает лимиты")
        snapshot = Snapshot(source="ldap", accounts=[Account(**row) for row in data["accounts"]],
            groups=[Group(**row) for row in data["groups"]], domain_policy=data["domain_policy"],
            computers=[Computer(**row) for row in data["computers"]],
            fine_grained_policies=data["fine_grained_policies"], spn_owners=data["spn_owners"],
            source_status={**data["source_status"], "ad_gateway": "pass"},
            auth_events=data["auth_events"])
        return classify_snapshot(snapshot)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # Library error text can contain a URL; never return a bearer token or internals.
        raise CollectorError(f"AD Gateway недоступен ({type(exc).__name__})") from exc
    except (ValueError, TypeError, KeyError) as exc:
        raise CollectorError("Gateway snapshot не прошёл проверку") from exc
