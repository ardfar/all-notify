(() => {
  "use strict";

  const KCV_INFO = "all-notify:v1:kcv";
  const B64URL_RE = /^[A-Za-z0-9_-]+$/;

  // Security invariant: K_master lives ONLY in tab memory (never storage/cookies/network).
  let masterKeyB64 = null;
  let serverKcv = null;
  let generatedKeyB64 = null;
  let activeCode = null;
  let pollTimer = null;
  let countdownTimer = null;
  let alertTimer = null;

  const $ = (id) => document.getElementById(id);

  function showAlert(msg, kind) {
    const el = $("global-alert");
    if (!msg) {
      el.classList.add("hidden");
      return;
    }
    el.textContent = msg;
    el.className = "alert " + (kind === "ok" ? "alert-ok" : "alert-error");
    clearTimeout(alertTimer);
    if (kind === "ok") {
      alertTimer = setTimeout(() => el.classList.add("hidden"), 4000);
    }
  }

  function bytesToBase64Url(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBytes(str) {
    const s = str.trim();
    if (!s || s.includes("=") || !B64URL_RE.test(s)) {
      throw new Error("Key must be unpadded base64url");
    }
    const std = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = std.length % 4 === 0 ? "" : "=".repeat(4 - (std.length % 4));
    const bin = atob(std + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    if (out.length !== 32 || bytesToBase64Url(out) !== s) {
      throw new Error("Key must be a canonical 32-byte base64url value");
    }
    return out;
  }

  function bytesToHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  async function computeKcv(keyB64) {
    const raw = base64UrlToBytes(keyB64);
    const key = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(KCV_INFO),
      },
      key,
      128
    );
    return bytesToHex(new Uint8Array(bits));
  }

  function generateMasterKey() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
  }

  function serverBaseUrl() {
    const path = window.location.pathname.replace(/\/admin(?:\/.*)?$/, "");
    return (window.location.origin + path).replace(/\/+$/, "");
  }

  function adminBasePath() {
    const path = window.location.pathname.replace(/\/admin(?:\/.*)?$/, "");
    return path.replace(/\/+$/, "") + "/admin";
  }

  function clearActiveQrDom() {
    activeCode = null;
    stopCodeTimers();
    $("qr-result").classList.add("hidden");
    $("qr-link-text").value = "";
    $("qr-image").removeAttribute("src");
    $("btn-download-qr").removeAttribute("href");
  }

  function clearKeyMaterialDom() {
    masterKeyB64 = null;
    generatedKeyB64 = null;
    clearActiveQrDom();
    $("generated-key-text").textContent = "";
    $("unlock-key-input").value = "";
    $("import-key-input").value = "";
  }

  function buildPairingUriV2(code, name) {
    return (
      "allnotify://pair?v=2" +
      "&url=" + encodeURIComponent(serverBaseUrl()) +
      "&code=" + encodeURIComponent(code) +
      "&key=" + encodeURIComponent(masterKeyB64) +
      "&name=" + encodeURIComponent(name)
    );
  }

  function renderQrPngDataUrl(text) {
    const qr = window.qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const count = qr.getModuleCount();
    const scale = 6;
    const margin = 4;
    const size = (count + margin * 2) * scale;
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = "#000000";
    for (let r = 0; r < count; r++) {
      for (let c = 0; c < count; c++) {
        if (qr.isDark(r, c)) {
          ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
        }
      }
    }
    return canvas.toDataURL("image/png");
  }

  async function api(method, path, body) {
    const fullPath = path.startsWith("/admin/") ? adminBasePath() + path.slice("/admin".length) : path;
    const headers = {};
    if (method !== "GET" && method !== "HEAD") {
      headers["X-AllNotify-Admin"] = "1";
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(fullPath, {
      method,
      headers,
      credentials: "same-origin",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try {
      data = await resp.json();
    } catch (_) {
      data = null;
    }
    if (!resp.ok) {
      const errCode = data && data.error ? data.error.code : "HTTP_" + resp.status;
      const errMsg = data && data.error ? data.error.message : "Request failed (" + resp.status + ")";
      if (resp.status === 401 && path !== "/admin/api/login" && errCode === "UNAUTHORIZED") {
        clearKeyMaterialDom();
        serverKcv = null;
        hideAllViews();
        $("topbar-actions").classList.add("hidden");
        $("view-login").classList.remove("hidden");
        $("login-password").focus();
        showAlert("Session expired. Please sign in again.", "error");
      }
      const err = new Error(errMsg);
      err.code = errCode;
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  function hideAllViews() {
    ["view-login", "view-force-password", "view-key-setup", "view-dashboard"].forEach((id) => {
      $(id).classList.add("hidden");
    });
  }

  function updateKeyBadge() {
    const badge = $("key-badge");
    if (masterKeyB64) {
      badge.textContent = "Key unlocked";
      badge.className = "badge badge-ok";
    } else {
      badge.textContent = "Key locked";
      badge.className = "badge badge-muted";
    }
    updateAddViewKeyState();
  }

  function updateAddViewKeyState() {
    const unlocked = Boolean(masterKeyB64);
    $("unlock-key-box").classList.toggle("hidden", unlocked);
    $("form-create-code").classList.toggle("hidden", !unlocked || Boolean(activeCode));
  }

  function stopCodeTimers() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  }

  function formatTime(ms) {
    if (!ms) return "never";
    return new Date(ms).toLocaleString();
  }

  async function refreshSession(keepAlert) {
    stopCodeTimers();
    if (!keepAlert) showAlert("");
    const sess = await api("GET", "/admin/api/session");
    hideAllViews();
    $("topbar-actions").classList.toggle("hidden", !sess.logged_in);

    if (!sess.logged_in) {
      clearKeyMaterialDom();
      serverKcv = null;
      $("view-login").classList.remove("hidden");
      $("login-password").focus();
      return;
    }
    if (sess.must_change_password) {
      $("view-force-password").classList.remove("hidden");
      $("fp-current").focus();
      return;
    }
    if (!sess.kcv_set) {
      initKeySetupView();
      $("view-key-setup").classList.remove("hidden");
      return;
    }

    const kcvRes = await api("GET", "/admin/api/kcv");
    serverKcv = kcvRes.kcv;
    $("settings-kcv").textContent = serverKcv || "-";
    updateKeyBadge();
    $("view-dashboard").classList.remove("hidden");
    await refreshDashboardData();
  }

  function initKeySetupView() {
    generatedKeyB64 = generateMasterKey();
    $("generated-key-text").textContent = generatedKeyB64;
    $("chk-saved-key").checked = false;
    $("btn-confirm-gen-key").disabled = true;
  }

  function setNav(tab) {
    ["devices", "add", "settings"].forEach((t) => {
      $("nav-" + t).classList.toggle("active", t === tab);
      $("section-" + t).classList.toggle("hidden", t !== tab);
    });
    if (tab === "devices") {
      refreshDashboardData().catch((e) => showAlert(e.message, "error"));
    } else if (tab === "add") {
      updateAddViewKeyState();
    }
  }

  async function refreshDashboardData() {
    const [devices, codes] = await Promise.all([
      api("GET", "/admin/api/devices"),
      api("GET", "/admin/api/pairing-codes"),
    ]);
    renderDevices(devices);
    renderCodes(codes);
  }

  function renderDevices(devices) {
    const container = $("devices-list");
    container.textContent = "";
    if (!devices || devices.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No devices registered yet. Switch to Add Device to pair your first device.";
      container.appendChild(empty);
      return;
    }

    devices.forEach((d) => {
      const row = document.createElement("div");
      row.className = "item-row";

      const main = document.createElement("div");
      main.className = "item-main";

      const title = document.createElement("div");
      title.className = "item-title";
      const dot = document.createElement("span");
      dot.className = "dot " + (d.revoked_at ? "dot-revoked" : d.online ? "dot-online" : "dot-offline");
      const nameSpan = document.createElement("span");
      nameSpan.textContent = d.name;
      const plat = document.createElement("span");
      plat.className = "badge";
      plat.textContent = d.platform;
      title.append(dot, nameSpan, plat);

      if (d.revoked_at) {
        const rev = document.createElement("span");
        rev.className = "badge badge-danger";
        rev.textContent = "Revoked";
        title.appendChild(rev);
      }

      const meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = d.id + " • Last seen: " + formatTime(d.last_seen);
      main.append(title, meta);

      const controls = document.createElement("div");
      controls.className = "item-controls";

      if (!d.revoked_at) {
        const trustLabel = document.createElement("label");
        trustLabel.className = "checkbox-row";
        const chk = document.createElement("input");
        chk.type = "checkbox";
        chk.checked = Boolean(d.can_add_devices);
        chk.addEventListener("change", async () => {
          chk.disabled = true;
          try {
            await api("PATCH", "/admin/api/devices/" + encodeURIComponent(d.id), {
              can_add_devices: chk.checked,
            });
            showAlert("Updated trust setting for " + d.name, "ok");
          } catch (e) {
            chk.checked = !chk.checked;
            showAlert(e.message, "error");
          } finally {
            chk.disabled = false;
          }
        });
        const lblText = document.createElement("span");
        lblText.textContent = "Can add devices";
        trustLabel.append(chk, lblText);

        const btnRename = document.createElement("button");
        btnRename.type = "button";
        btnRename.className = "btn btn-ghost";
        btnRename.textContent = "Rename";
        btnRename.addEventListener("click", async () => {
          const next = window.prompt("New name for " + d.name + ":", d.name);
          if (!next || next.trim() === "" || next.trim() === d.name) return;
          try {
            await api("PATCH", "/admin/api/devices/" + encodeURIComponent(d.id), { name: next.trim() });
            showAlert("Renamed device", "ok");
            await refreshDashboardData();
          } catch (e) {
            showAlert(e.message, "error");
          }
        });

        const btnRevoke = document.createElement("button");
        btnRevoke.type = "button";
        btnRevoke.className = "btn btn-danger";
        btnRevoke.textContent = "Revoke";
        btnRevoke.addEventListener("click", async () => {
          if (!window.confirm("Revoke " + d.name + "? It will be disconnected immediately.")) return;
          try {
            await api("POST", "/admin/api/devices/" + encodeURIComponent(d.id) + "/revoke");
            showAlert("Revoked " + d.name, "ok");
            await refreshDashboardData();
          } catch (e) {
            showAlert(e.message, "error");
          }
        });

        controls.append(trustLabel, btnRename, btnRevoke);
      }

      row.append(main, controls);
      container.appendChild(row);
    });
  }

  function renderCodes(codes) {
    const container = $("codes-list");
    container.textContent = "";
    if (!codes || codes.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No pairing codes created in the last 24 hours.";
      container.appendChild(empty);
      return;
    }

    codes.forEach((c) => {
      const row = document.createElement("div");
      row.className = "item-row";

      const main = document.createElement("div");
      main.className = "item-main";
      const title = document.createElement("div");
      title.className = "item-title";
      const nameSpan = document.createElement("span");
      nameSpan.textContent = c.name;
      const plat = document.createElement("span");
      plat.className = "badge";
      plat.textContent = c.platform;
      const st = document.createElement("span");
      st.className =
        "badge " +
        (c.status === "claimed" ? "badge-ok" : c.status === "pending" ? "badge-warn" : "badge-muted");
      st.textContent = c.status;
      title.append(nameSpan, plat, st);

      const meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = c.code_id + " • Expires: " + formatTime(c.expires_at);
      main.append(title, meta);

      const controls = document.createElement("div");
      controls.className = "item-controls";
      if (c.status === "pending") {
        const btnCancel = document.createElement("button");
        btnCancel.type = "button";
        btnCancel.className = "btn btn-danger";
        btnCancel.textContent = "Cancel";
        btnCancel.addEventListener("click", async () => {
          try {
            await api("DELETE", "/admin/api/pairing-codes/" + encodeURIComponent(c.code_id));
            if (activeCode && activeCode.code_id === c.code_id) {
              stopCodeTimers();
              $("qr-status-badge").textContent = "Cancelled";
              $("qr-status-badge").className = "badge badge-muted";
              $("btn-cancel-active-code").classList.add("hidden");
            }
            showAlert("Cancelled pairing code", "ok");
            await refreshDashboardData();
          } catch (e) {
            showAlert(e.message, "error");
          }
        });
        controls.appendChild(btnCancel);
      }

      row.append(main, controls);
      container.appendChild(row);
    });
  }

  function showActiveQr(created) {
    stopCodeTimers();
    activeCode = created;
    const uri = buildPairingUriV2(created.code, created.name);
    const pngUrl = renderQrPngDataUrl(uri);

    $("qr-device-title").textContent = created.name + " (" + created.platform + ")";
    $("qr-status-badge").textContent = "Pending";
    $("qr-status-badge").className = "badge badge-warn";
    $("qr-image").src = pngUrl;
    $("btn-download-qr").href = pngUrl;
    $("qr-link-text").value = uri;
    $("btn-cancel-active-code").classList.remove("hidden");
    $("qr-result").classList.remove("hidden");
    $("form-create-code").classList.add("hidden");

    const tickCountdown = () => {
      if (!activeCode) return;
      const rem = Math.max(0, Math.floor((activeCode.expires_at - Date.now()) / 1000));
      const m = Math.floor(rem / 60);
      const s = String(rem % 60).padStart(2, "0");
      $("qr-countdown").textContent = rem > 0 ? "Expires in " + m + ":" + s : "Expired";
      if (rem === 0) {
        $("qr-status-badge").textContent = "Expired";
        $("qr-status-badge").className = "badge badge-muted";
        $("btn-cancel-active-code").classList.add("hidden");
        stopCodeTimers();
      }
    };
    tickCountdown();
    countdownTimer = setInterval(tickCountdown, 1000);

    pollTimer = setInterval(async () => {
      if (!activeCode) return;
      try {
        const list = await api("GET", "/admin/api/pairing-codes");
        const found = list.find((item) => item.code_id === activeCode.code_id);
        if (!found) return;
        if (found.status === "claimed") {
          $("qr-status-badge").textContent = "Claimed \u2713";
          $("qr-status-badge").className = "badge badge-ok";
          $("qr-countdown").textContent = "Device paired!";
          $("btn-cancel-active-code").classList.add("hidden");
          stopCodeTimers();
        } else if (found.status === "cancelled" || found.status === "expired") {
          $("qr-status-badge").textContent = found.status === "cancelled" ? "Cancelled" : "Expired";
          $("qr-status-badge").className = "badge badge-muted";
          $("btn-cancel-active-code").classList.add("hidden");
          stopCodeTimers();
        }
      } catch (_) {
        // Ignore transient poll errors
      }
    }, 3000);
  }

  // Wire UI event listeners
  $("form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    try {
      await api("POST", "/admin/api/login", { password: $("login-password").value });
      $("login-password").value = "";
      await refreshSession();
    } catch (err) {
      showAlert(err.message, "error");
    }
  });

  $("btn-logout").addEventListener("click", async () => {
    clearKeyMaterialDom();
    serverKcv = null;
    try {
      await api("POST", "/admin/api/logout");
    } catch (_) {}
    await refreshSession();
  });

  async function submitPasswordChange(curId, newId, confId) {
    showAlert("");
    const current = $(curId).value;
    const next = $(newId).value;
    const conf = $(confId).value;
    if (next.length < 12) {
      showAlert("New password must be at least 12 characters.", "error");
      return;
    }
    if (next !== conf) {
      showAlert("New passwords do not match.", "error");
      return;
    }
    try {
      await api("POST", "/admin/api/password", { current, new: next });
      $(curId).value = "";
      $(newId).value = "";
      $(confId).value = "";
      showAlert("Admin password updated.", "ok");
      await refreshSession(true);
    } catch (err) {
      showAlert(err.message, "error");
    }
  }

  $("form-force-password").addEventListener("submit", (e) => {
    e.preventDefault();
    submitPasswordChange("fp-current", "fp-new", "fp-confirm");
  });

  $("form-settings-password").addEventListener("submit", (e) => {
    e.preventDefault();
    submitPasswordChange("sp-current", "sp-new", "sp-confirm");
  });

  $("tab-gen-key").addEventListener("click", () => {
    $("tab-gen-key").classList.add("active");
    $("tab-import-key").classList.remove("active");
    $("panel-gen-key").classList.remove("hidden");
    $("panel-import-key").classList.add("hidden");
  });

  $("tab-import-key").addEventListener("click", () => {
    $("tab-import-key").classList.add("active");
    $("tab-gen-key").classList.remove("active");
    $("panel-import-key").classList.remove("hidden");
    $("panel-gen-key").classList.add("hidden");
  });

  $("btn-regen-key").addEventListener("click", initKeySetupView);

  $("btn-copy-gen-key").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(generatedKeyB64);
      showAlert("Copied K_master to clipboard.", "ok");
    } catch (_) {
      showAlert("Clipboard unavailable — select and copy the key manually.", "error");
    }
  });

  $("btn-download-gen-key").addEventListener("click", () => {
    const blob = new Blob(
      ["All-Notify Master Encryption Key (K_master)\nKeep secret; never store on VPS.\n\n" + generatedKeyB64 + "\n"],
      { type: "text/plain" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "all-notify-key.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  $("chk-saved-key").addEventListener("change", () => {
    $("btn-confirm-gen-key").disabled = !$("chk-saved-key").checked;
  });

  $("btn-confirm-gen-key").addEventListener("click", async () => {
    showAlert("");
    try {
      const kcv = await computeKcv(generatedKeyB64);
      await api("PUT", "/admin/api/kcv", { kcv });
      masterKeyB64 = generatedKeyB64;
      generatedKeyB64 = null;
      $("generated-key-text").textContent = "";
      await refreshSession();
      setNav("add");
    } catch (err) {
      showAlert(err.message, "error");
    }
  });

  $("form-import-key").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    try {
      const key = $("import-key-input").value.trim();
      const kcv = await computeKcv(key);
      await api("PUT", "/admin/api/kcv", { kcv });
      masterKeyB64 = key;
      $("import-key-input").value = "";
      await refreshSession();
      setNav("add");
    } catch (err) {
      showAlert(err.message, "error");
    }
  });

  $("form-unlock-key").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    try {
      const key = $("unlock-key-input").value.trim();
      const kcv = await computeKcv(key);
      if (serverKcv && kcv !== serverKcv) {
        showAlert("Key check value mismatch! This is not the group's K_master.", "error");
        return;
      }
      masterKeyB64 = key;
      $("unlock-key-input").value = "";
      updateKeyBadge();
      showAlert("Group key unlocked in this tab.", "ok");
    } catch (err) {
      showAlert(err.message, "error");
    }
  });

  $("btn-lock-key").addEventListener("click", () => {
    clearKeyMaterialDom();
    updateKeyBadge();
    showAlert("Group key cleared from tab memory.", "ok");
  });

  $("form-create-code").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    if (!masterKeyB64) {
      showAlert("Unlock your group key first.", "error");
      return;
    }
    try {
      const created = await api("POST", "/admin/api/pairing-codes", {
        name: $("new-dev-name").value.trim(),
        platform: $("new-dev-platform").value,
        can_add_devices: $("new-dev-trusted").checked,
      });
      $("new-dev-name").value = "";
      $("new-dev-trusted").checked = false;
      showActiveQr(created);
    } catch (err) {
      showAlert(err.message, "error");
    }
  });

  $("btn-copy-link").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("qr-link-text").value);
      showAlert("Pairing link copied.", "ok");
    } catch (_) {
      $("qr-link-text").select();
      showAlert("Clipboard unavailable — link selected for manual copy.", "error");
    }
  });

  $("btn-cancel-active-code").addEventListener("click", async () => {
    if (!activeCode) return;
    try {
      await api("DELETE", "/admin/api/pairing-codes/" + encodeURIComponent(activeCode.code_id));
      stopCodeTimers();
      $("qr-status-badge").textContent = "Cancelled";
      $("qr-status-badge").className = "badge badge-muted";
      $("btn-cancel-active-code").classList.add("hidden");
      showAlert("Pairing code cancelled.", "ok");
    } catch (err) {
      showAlert(err.message, "error");
    }
  });

  $("btn-new-code").addEventListener("click", () => {
    clearActiveQrDom();
    updateAddViewKeyState();
  });

  $("nav-devices").addEventListener("click", () => setNav("devices"));
  $("nav-add").addEventListener("click", () => setNav("add"));
  $("nav-settings").addEventListener("click", () => setNav("settings"));
  $("btn-refresh-devices").addEventListener("click", () => {
    refreshDashboardData().catch((e) => showAlert(e.message, "error"));
  });

  refreshSession().catch((err) => showAlert(err.message, "error"));
})();
