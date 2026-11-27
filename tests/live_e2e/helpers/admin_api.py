"""HTTP & Playwright helpers for testing the live All-Notify server & /admin web UI."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass
class HttpResp:
    status: int
    headers: dict[str, str]
    body: str

    def json(self) -> dict | list:
        return json.loads(self.body) if self.body else {}


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    opener: urllib.request.OpenerDirector | None = None,
    timeout: float = 15.0,
) -> HttpResp:
    req_headers = {"User-Agent": "All-Notify-E2E/1.0"}
    if headers:
        req_headers.update(headers)
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    do_open = opener.open if opener is not None else urllib.request.urlopen
    try:
        with do_open(req, timeout=timeout) as resp:
            return HttpResp(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=resp.read().decode("utf-8", errors="replace"),
            )
    except urllib.error.HTTPError as err:
        return HttpResp(
            status=err.code,
            headers={k.lower(): v for k, v in err.headers.items()},
            body=err.read().decode("utf-8", errors="replace"),
        )


def compute_kcv_hex(k_master_b64url: str) -> str:
    """Compute hex(HKDF-SHA256(K_master, salt='', info='all-notify:v1:kcv', len=16))."""
    pad = "=" * ((4 - len(k_master_b64url) % 4) % 4)
    ikm = base64.urlsafe_b64decode(k_master_b64url + pad)
    if len(ikm) != 32:
        raise ValueError(f"K_master must decode to 32 bytes, got {len(ikm)}")
    # HKDF-Extract with empty salt -> 32 zero bytes
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    # HKDF-Expand single block (T(1) = HMAC(PRK, info || 0x01))
    okm = hmac.new(prk, b"all-notify:v1:kcv\x01", hashlib.sha256).digest()[:16]
    return okm.hex()


class AdminHttpClient:
    """Cookie-jar backed admin API client for clean setup/teardown and API assertions."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _headers(self, *, csrf: bool = True) -> dict[str, str]:
        h: dict[str, str] = {"Origin": self.base_url}
        if csrf:
            h["X-AllNotify-Admin"] = "1"
        return h

    def login(self, password: str) -> HttpResp:
        return http_request(
            "POST",
            f"{self.base_url}/admin/api/login",
            headers=self._headers(),
            json_body={"password": password},
            opener=self.opener,
        )

    def logout(self) -> HttpResp:
        return http_request(
            "POST",
            f"{self.base_url}/admin/api/logout",
            headers=self._headers(),
            opener=self.opener,
        )

    def session(self) -> HttpResp:
        return http_request(
            "GET",
            f"{self.base_url}/admin/api/session",
            headers=self._headers(),
            opener=self.opener,
        )

    def list_devices(self) -> HttpResp:
        return http_request(
            "GET",
            f"{self.base_url}/admin/api/devices",
            headers=self._headers(),
            opener=self.opener,
        )

    def create_pairing_code(
        self, name: str, platform: str, can_add_devices: bool = False, *, csrf: bool = True
    ) -> HttpResp:
        return http_request(
            "POST",
            f"{self.base_url}/admin/api/pairing-codes",
            headers=self._headers(csrf=csrf),
            json_body={"name": name, "platform": platform, "can_add_devices": can_add_devices},
            opener=self.opener,
        )

    def cancel_pairing_code(self, code_id: str) -> HttpResp:
        return http_request(
            "DELETE",
            f"{self.base_url}/admin/api/pairing-codes/{urllib.parse.quote(code_id, safe='')}",
            headers=self._headers(),
            opener=self.opener,
        )

    def patch_device(self, device_id: str, **fields: object) -> HttpResp:
        return http_request(
            "PATCH",
            f"{self.base_url}/admin/api/devices/{urllib.parse.quote(device_id, safe='')}",
            headers=self._headers(),
            json_body=fields,
            opener=self.opener,
        )

    def revoke_device(self, device_id: str) -> HttpResp:
        return http_request(
            "POST",
            f"{self.base_url}/admin/api/devices/{urllib.parse.quote(device_id, safe='')}/revoke",
            headers=self._headers(),
            opener=self.opener,
        )
