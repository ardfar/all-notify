"""T02: Live Admin Web UI (Playwright) & Phase 5 Pairing/Trust/Revocation API verification."""

from __future__ import annotations

import os
import time
import urllib.parse

from helpers import admin_api
from helpers.report import SkipCheck, TestContext


def run(ctx: TestContext) -> None:
    print("\n=== T02: Admin Web UI & Phase 5 Pairing Lifecycle ===")

    def check_security_headers():
        resp = admin_api.http_request("GET", f"{ctx.server_url}/admin")
        assert resp.status == 200, f"GET /admin returned {resp.status}"
        h = resp.headers
        csp = h.get("content-security-policy", "")
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp, f"weak CSP: {csp!r}"
        assert h.get("x-frame-options", "").upper() == "DENY", f"bad X-Frame-Options: {h.get('x-frame-options')}"
        assert h.get("referrer-policy") == "no-referrer", f"bad Referrer-Policy: {h.get('referrer-policy')}"
        assert "no-store" in h.get("cache-control", ""), f"bad Cache-Control: {h.get('cache-control')}"
        assert h.get("x-content-type-options") == "nosniff", f"bad X-Content-Type-Options: {h.get('x-content-type-options')}"
        return ("PASS", "CSP, X-Frame-Options, Referrer-Policy, Cache-Control, nosniff verified", {"csp": csp})

    ctx.record("T02.1", "admin", "Admin page strict security headers & CSP", check_security_headers)

    if not ctx.admin_password:
        ctx.record(
            "T02.2",
            "admin",
            "Admin auth, CSRF, device inventory & throwaway pairing lifecycle",
            lambda: (_ for _ in ()).throw(
                SkipCheck("ALLNOTIFY_ADMIN_PASSWORD not provided; skipped authenticated admin checks")
            ),
        )
        return

    client = admin_api.AdminHttpClient(ctx.server_url)

    def check_login_and_csrf():
        login = client.login(ctx.admin_password)
        assert login.status == 200, f"admin login failed ({login.status}): {login.body}"
        sess = client.session()
        assert sess.status == 200, f"session check failed ({sess.status})"
        sdata = sess.json()
        assert sdata.get("logged_in") is True, f"expected logged_in=true, got {sdata}"
        assert not sdata.get("must_change_password"), "admin account still requires initial password change"
        ctx.meta["admin_kcv_set"] = bool(sdata.get("kcv_set"))

        # Verify CSRF guard rejects state-changing call missing X-AllNotify-Admin header
        no_csrf = client.create_pairing_code(f"csrf-reject-{ctx.run_id}", "android", csrf=False)
        assert no_csrf.status in (400, 403), (
            f"expected 400/403 when X-AllNotify-Admin header omitted, got {no_csrf.status}"
        )
        return ("PASS", f"login ok (kcv_set={sdata.get('kcv_set')}); missing CSRF header rejected ({no_csrf.status})", {})

    ctx.record("T02.2", "admin", "Admin login, session & CSRF rejection", check_login_and_csrf)

    def check_inventory():
        resp = client.list_devices()
        assert resp.status == 200, f"GET /admin/api/devices failed: {resp.status}"
        raw = resp.json()
        devices = raw.get("devices", raw) if isinstance(raw, dict) else raw
        active = [d for d in devices if not d.get("revoked_at")]
        online = [d for d in active if d.get("online")]
        mac_id = ctx.meta.get("mac_device_id")
        if mac_id:
            mac_row = next((d for d in active if d.get("id") == mac_id), None)
            assert mac_row is not None, f"MacBook {mac_id} not found in active admin device list"
            assert mac_row.get("online"), f"MacBook {mac_id} appears offline on VPS"
        online_android = [d for d in online if d.get("platform") == "android"]
        expected_android = sum(1 for s in (ctx.phone_a, ctx.phone_b) if s)
        status = "PASS" if len(online_android) >= expected_android else "WARN"
        ctx.meta["online_devices"] = [
            {"id": d.get("id"), "name": d.get("name"), "platform": d.get("platform"), "trusted": d.get("can_add_devices")}
            for d in online
        ]
        return (
            status,
            f"{len(online)}/{len(active)} active devices online (android online={len(online_android)}, expected>={expected_android})",
            {"online_count": len(online), "android_online": len(online_android)},
        )

    ctx.record("T02.3", "admin", "Registered devices & live online status", check_inventory)

    def check_throwaway_pairing_lifecycle():
        tmp_name = f"e2e-tmp-{ctx.run_id}"
        claimed_dev_id: str | None = None
        child_code_id: str | None = None
        try:
            # 1. Create one-time code (untrusted)
            cr = client.create_pairing_code(tmp_name, "macos", can_add_devices=False)
            assert cr.status in (200, 201), f"create pairing code failed ({cr.status}): {cr.body}"
            cdata = cr.json()
            code = cdata["code"]
            assert code.startswith("pc_"), f"unexpected code format: {code[:6]}..."

            # 2. Claim via public POST /v1/pair/claim
            claim = admin_api.http_request(
                "POST",
                f"{ctx.server_url}/v1/pair/claim",
                json_body={"code": code, "platform": "macos"},
            )
            assert claim.status == 200, f"claim failed ({claim.status}): {claim.body}"
            claimed = claim.json()
            claimed_dev_id = claimed["device_id"]
            dev_token = claimed["token"]
            assert claimed.get("can_add_devices") is False, "expected untrusted device initially"

            # 3. Second claim of same code must return 410 Gone
            reclaim = admin_api.http_request(
                "POST",
                f"{ctx.server_url}/v1/pair/claim",
                json_body={"code": code, "platform": "macos"},
            )
            assert reclaim.status == 410, f"double-claim must return 410, got {reclaim.status}: {reclaim.body}"

            auth_hdr = {"Authorization": f"Bearer {dev_token}"}

            # 4. Untrusted device cannot create pairing codes (403)
            untrusted = admin_api.http_request(
                "POST",
                f"{ctx.server_url}/v1/pairing-codes",
                headers=auth_hdr,
                json_body={"name": "should-fail", "platform": "android"},
            )
            assert untrusted.status == 403, f"untrusted POST /v1/pairing-codes must be 403, got {untrusted.status}"

            # 5. Admin renames device and grants trust
            renamed = f"{tmp_name}-renamed"
            patch = client.patch_device(claimed_dev_id, name=renamed, can_add_devices=True)
            assert patch.status == 200, f"PATCH device failed ({patch.status}): {patch.body}"

            me = admin_api.http_request("GET", f"{ctx.server_url}/v1/me", headers=auth_hdr)
            assert me.status == 200, f"GET /v1/me failed ({me.status})"
            me_data = me.json()
            assert me_data.get("name") == renamed and me_data.get("can_add_devices") is True, (
                f"GET /v1/me mismatch: {me_data}"
            )

            # 6. Trusted device creates child pairing code; cancel it and verify 410
            child = admin_api.http_request(
                "POST",
                f"{ctx.server_url}/v1/pairing-codes",
                headers=auth_hdr,
                json_body={"name": f"e2e-child-{ctx.run_id}", "platform": "android"},
            )
            assert child.status in (200, 201), f"trusted POST /v1/pairing-codes failed ({child.status}): {child.body}"
            child_data = child.json()
            child_code_id = child_data["code_id"]
            child_code = child_data["code"]

            # List own codes must NOT return raw secret `code`
            listed = admin_api.http_request("GET", f"{ctx.server_url}/v1/pairing-codes", headers=auth_hdr)
            assert listed.status == 200, f"GET /v1/pairing-codes failed: {listed.status}"
            assert child_code not in listed.body, "SECURITY: GET /v1/pairing-codes leaked raw pairing code!"

            cancel = client.cancel_pairing_code(child_code_id)
            assert cancel.status in (200, 204), f"cancel pairing code failed: {cancel.status}"
            child_code_id = None

            claim_cancelled = admin_api.http_request(
                "POST",
                f"{ctx.server_url}/v1/pair/claim",
                json_body={"code": child_code, "platform": "android"},
            )
            assert claim_cancelled.status == 410, (
                f"claiming cancelled code must return 410, got {claim_cancelled.status}"
            )

            # 7. Revoke throwaway device and confirm immediate 401
            rev = client.revoke_device(claimed_dev_id)
            assert rev.status in (200, 204), f"revoke failed ({rev.status}): {rev.body}"
            revoked_me = admin_api.http_request("GET", f"{ctx.server_url}/v1/me", headers=auth_hdr)
            assert revoked_me.status == 401, f"revoked device must get 401 on /v1/me, got {revoked_me.status}"
            claimed_dev_id = None

            return (
                "PASS",
                "create->claim->410 replay->403 untrusted->rename+trust->trusted code->cancel 410->revoke 401",
                {},
            )
        finally:
            if child_code_id:
                client.cancel_pairing_code(child_code_id)
            if claimed_dev_id:
                client.revoke_device(claimed_dev_id)

    ctx.record("T02.4", "admin", "Throwaway v2 pairing, trust, cancel & revocation API lifecycle", check_throwaway_pairing_lifecycle)

    def check_playwright_ui():
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise SkipCheck(f"playwright not installed: {exc}")

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            console_errors: list[str] = []
            page.on("pageerror", lambda err: console_errors.append(str(err)))
            try:
                page.goto(f"{ctx.server_url}/admin", wait_until="networkidle", timeout=20000)
                page.fill("#login-password", ctx.admin_password)
                page.click('#form-login button[type="submit"]')
                page.wait_for_selector("#view-dashboard:not(.hidden)", timeout=10000)
                page.wait_for_selector("#devices-list > *", timeout=10000)

                qr_detail = "dashboard loaded"
                if ctx.k_master:
                    page.click("#nav-add")
                    page.wait_for_selector("#section-add:not(.hidden)", timeout=5000)

                    # Verify wrong key is rejected locally by KCV check
                    wrong_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    if wrong_key == ctx.k_master:
                        wrong_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    page.fill("#unlock-key-input", wrong_key)
                    page.click('#form-unlock-key button[type="submit"]')
                    page.wait_for_selector("#global-alert:not(.hidden)", timeout=5000)

                    # Unlock with real K_master
                    page.fill("#unlock-key-input", ctx.k_master)
                    page.click('#form-unlock-key button[type="submit"]')
                    page.wait_for_selector("#form-create-code:not(.hidden)", timeout=5000)

                    # Generate throwaway QR, validate v2 link, then cancel immediately
                    page.fill("#new-dev-name", f"e2e-ui-{ctx.run_id}")
                    page.select_option("#new-dev-platform", "android")
                    page.click('#form-create-code button[type="submit"]')
                    page.wait_for_selector("#qr-result:not(.hidden)", timeout=10000)

                    qr_src = page.get_attribute("#qr-image", "src") or ""
                    link_val = page.input_value("#qr-link-text")
                    assert qr_src.startswith("data:image/"), f"QR image did not render: {qr_src[:30]}"
                    parsed = urllib.parse.urlparse(link_val)
                    qs = urllib.parse.parse_qs(parsed.query)
                    assert parsed.scheme == "allnotify" and parsed.netloc == "pair", "bad pairing URI scheme"
                    assert qs.get("v") == ["2"], f"expected v=2, got {qs.get('v')}"
                    assert qs.get("code", [""])[0].startswith("pc_"), "missing pc_ code in v2 link"
                    assert "token" not in qs and "device_id" not in qs, "v2 link must not contain token/device_id"
                    assert qs.get("key") == [ctx.k_master], "key mismatch in generated v2 link"

                    # Cancel the throwaway code cleanly
                    page.click("#btn-cancel-active-code")
                    time.sleep(0.5)

                    # Prove K_master is NOT persisted in localStorage, sessionStorage, or cookies
                    leaked = page.evaluate(
                        """(k) => {
                            const ls = JSON.stringify(localStorage);
                            const ss = JSON.stringify(sessionStorage);
                            const ck = document.cookie || '';
                            return ls.includes(k) || ss.includes(k) || ck.includes(k);
                        }""",
                        ctx.k_master,
                    )
                    assert not leaked, "SECURITY: K_master found in localStorage/sessionStorage/cookie!"
                    qr_detail = "dashboard + wrong-key KCV rejection + v2 QR render + cancel + zero browser storage leak"

                assert not console_errors, f"browser page errors: {console_errors}"
                return ("PASS", qr_detail, {})
            finally:
                browser.close()

    ctx.record("T02.5", "admin", "Playwright Chromium /admin UI, KCV gate & tab-memory-only proof", check_playwright_ui)

    client.logout()
