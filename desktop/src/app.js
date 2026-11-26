const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const els = {
  statusDot: document.getElementById("status-dot"),
  statusLabel: document.getElementById("status-label"),
  headerActions: document.getElementById("header-actions"),
  btnMute: document.getElementById("btn-mute"),
  btnClearAll: document.getElementById("btn-clear-all"),
  btnSettings: document.getElementById("btn-settings"),

  viewPairing: document.getElementById("view-pairing"),
  pairBackRow: document.getElementById("pair-back-row"),
  btnPairCancel: document.getElementById("btn-pair-cancel"),
  qrDropzone: document.getElementById("qr-dropzone"),
  qrFileInput: document.getElementById("qr-file-input"),
  pairUriInput: document.getElementById("pair-uri-input"),
  pairError: document.getElementById("pair-error"),
  pairConfirmReplace: document.getElementById("pair-confirm-replace"),
  btnConfirmReplace: document.getElementById("btn-confirm-replace"),
  btnCancelReplace: document.getElementById("btn-cancel-replace"),
  btnPairSubmit: document.getElementById("btn-pair-submit"),

  viewFeed: document.getElementById("view-feed"),
  authErrorBanner: document.getElementById("auth-error-banner"),
  btnAuthSettings: document.getElementById("btn-auth-settings"),
  searchInput: document.getElementById("search-input"),
  feedList: document.getElementById("feed-list"),

  viewSettings: document.getElementById("view-settings"),
  btnBackFeed: document.getElementById("btn-back-feed"),
  setDeviceName: document.getElementById("set-device-name"),
  setServerUrl: document.getElementById("set-server-url"),
  toggleAutostart: document.getElementById("toggle-autostart"),
  togglePrivacy: document.getElementById("toggle-privacy"),
  inputRetDays: document.getElementById("input-ret-days"),
  inputRetRows: document.getElementById("input-ret-rows"),
  btnSaveRetention: document.getElementById("btn-save-retention"),
  settingsFeedback: document.getElementById("settings-feedback"),
  cardAddDevice: document.getElementById("card-add-device"),
  btnOpenAddDevice: document.getElementById("btn-open-add-device"),
  btnOpenRepair: document.getElementById("btn-open-repair"),
  btnClearHistory: document.getElementById("btn-clear-history"),
  btnUnpair: document.getElementById("btn-unpair"),

  viewAddDevice: document.getElementById("view-add-device"),
  btnBackSettings: document.getElementById("btn-back-settings"),
  addDeviceFormCard: document.getElementById("add-device-form-card"),
  addDevName: document.getElementById("add-dev-name"),
  addDevPlatform: document.getElementById("add-dev-platform"),
  addDevError: document.getElementById("add-dev-error"),
  btnGenerateQr: document.getElementById("btn-generate-qr"),
  addDeviceQrCard: document.getElementById("add-device-qr-card"),
  addQrTitle: document.getElementById("add-qr-title"),
  addQrStatus: document.getElementById("add-qr-status"),
  addQrCountdown: document.getElementById("add-qr-countdown"),
  addQrImg: document.getElementById("add-qr-img"),
  addQrUri: document.getElementById("add-qr-uri"),
  btnCopyAddUri: document.getElementById("btn-copy-add-uri"),
  btnAddAnother: document.getElementById("btn-add-another"),
  addQrFeedback: document.getElementById("add-qr-feedback"),

  lightbox: document.getElementById("lightbox"),
  lightboxImg: document.getElementById("lightbox-img"),
  lightboxClose: document.getElementById("lightbox-close"),
};

let appState = null;
let showingSettings = false;
let showingAddDevice = false;
let showingRepair = false;
let pendingReplaceUri = null;
let activeAddCode = null;
let addPollTimer = null;
let addCountdownTimer = null;
let addQrFeedbackTimer = null;
let searchTimer = null;
let feedbackTimer = null;
let feedRequestSeq = 0;
let confirmTimers = { clearHistory: null, unpair: null };

const MAX_ICON_CACHE = 200;
const MAX_ATTACHMENT_CACHE = 30;
const MAX_QR_IMAGE_BYTES = 10 * 1024 * 1024;
const iconCache = new Map();
const attachmentCache = new Map();

function cacheSet(map, key, value, maxEntries) {
  if (map.has(key)) {
    map.delete(key);
  } else if (map.size >= maxEntries) {
    const oldestKey = map.keys().next().value;
    if (oldestKey !== undefined) map.delete(oldestKey);
  }
  map.set(key, value);
}

function cacheGet(map, key) {
  if (!map.has(key)) return undefined;
  const val = map.get(key);
  map.delete(key);
  map.set(key, val);
  return val;
}

function statusText(state) {
  if (!state || !state.paired) return "Not paired";
  if (state.status === "unauthorized") return "Access revoked";
  if (state.muted) return "Paused / Muted";
  switch (state.status) {
    case "connected":
      return state.unread_count > 0 ? `Connected · ${state.unread_count} active` : "Connected";
    case "connecting":
      return "Connecting...";
    case "reconnecting":
      return "Reconnecting...";
    default:
      return "Disconnected";
  }
}

function statusDotClass(state) {
  if (!state || !state.paired) return "unpaired";
  if (state.status === "unauthorized") return "unauthorized";
  if (state.muted) return "muted";
  return state.status || "disconnected";
}

function formatRelativeTime(unixMs) {
  const diffSec = Math.max(0, Math.floor((Date.now() - unixMs) / 1000));
  if (diffSec < 45) return "now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h`;
  return `${Math.floor(diffSec / 86400)}d`;
}

function syncRetentionInputs() {
  if (appState && appState.retention) {
    els.inputRetDays.value = appState.retention.days;
    els.inputRetRows.value = appState.retention.max_rows;
  }
}

function stopAddDeviceTimers() {
  if (addPollTimer) { clearInterval(addPollTimer); addPollTimer = null; }
  if (addCountdownTimer) { clearInterval(addCountdownTimer); addCountdownTimer = null; }
}

function setContentProtection(enabled) {
  invoke("set_content_protected", { protected: enabled }).catch(() => {});
}

function exitAddDeviceView() {
  stopAddDeviceTimers();
  clearTimeout(addQrFeedbackTimer);
  activeAddCode = null;
  showingAddDevice = false;
  els.addDeviceQrCard.classList.add("hidden");
  els.addDeviceFormCard.classList.remove("hidden");
  els.addQrImg.removeAttribute("src");
  els.addQrUri.value = "";
  els.addDevError.classList.add("hidden");
  els.addQrFeedback.classList.add("hidden");
  setContentProtection(false);
}

function renderHeaderAndViews() {
  els.statusDot.className = `status-dot ${statusDotClass(appState)}`;
  els.statusLabel.textContent = statusText(appState);

  const paired = Boolean(appState && appState.paired);
  const canAdd = Boolean(appState && appState.can_add_devices);
  if (!paired || !canAdd) {
    if (showingAddDevice) exitAddDeviceView();
  }
  if (!paired) {
    showingRepair = false;
  }

  const showPairing = !paired || showingRepair;
  els.headerActions.classList.toggle("hidden", !paired);
  els.btnMute.classList.toggle("active", Boolean(appState && appState.muted));
  els.btnMute.title = appState && appState.muted ? "Resume notifications" : "Pause / Mute notifications";

  els.viewPairing.classList.toggle("hidden", !showPairing);
  els.pairBackRow.classList.toggle("hidden", !paired);
  els.viewFeed.classList.toggle("hidden", showPairing || showingSettings || showingAddDevice);
  els.viewSettings.classList.toggle("hidden", showPairing || !showingSettings || showingAddDevice);
  els.viewAddDevice.classList.toggle("hidden", !paired || !canAdd || !showingAddDevice);
  els.authErrorBanner.classList.toggle(
    "hidden",
    !paired || appState.status !== "unauthorized"
  );

  if (paired) {
    els.setDeviceName.textContent = appState.device_name || "—";
    els.setServerUrl.textContent = appState.server_url || "—";
    els.toggleAutostart.checked = Boolean(appState.autostart);
    els.togglePrivacy.checked = Boolean(appState.privacy_mode);
    els.cardAddDevice.classList.toggle("hidden", !canAdd);
    if (!showingSettings) {
      syncRetentionInputs();
    }
  }
}

async function refreshState() {
  appState = await invoke("get_app_state");
  if (!appState.paired) {
    showingSettings = false;
    showingRepair = false;
    if (showingAddDevice) exitAddDeviceView();
  }
  renderHeaderAndViews();
}

async function loadIcon(sha256, container) {
  if (!sha256) return;
  const cached = cacheGet(iconCache, sha256);
  if (cached) {
    applyIconImg(container, cached);
    return;
  }
  try {
    const url = await invoke("read_icon_data_url", { sha256 });
    if (url) {
      cacheSet(iconCache, sha256, url, MAX_ICON_CACHE);
      applyIconImg(container, url);
    }
  } catch {
    // Do not permanently cache transient IPC/read failures.
  }
}

function applyIconImg(container, dataUrl) {
  const img = document.createElement("img");
  img.src = dataUrl;
  img.alt = "";
  container.textContent = "";
  container.appendChild(img);
}

async function loadAttachment(rowId, parent) {
  const cached = cacheGet(attachmentCache, rowId);
  if (cached) {
    appendThumb(parent, cached);
    return;
  }
  try {
    const url = await invoke("read_attachment_data_url", { rowId });
    if (url) {
      cacheSet(attachmentCache, rowId, url, MAX_ATTACHMENT_CACHE);
      appendThumb(parent, url);
    }
  } catch {
    // Do not permanently cache transient IPC/read failures.
  }
}

function appendThumb(parent, dataUrl) {
  const img = document.createElement("img");
  img.className = "notif-thumb";
  img.src = dataUrl;
  img.alt = "Notification image attachment";
  img.addEventListener("click", () => {
    els.lightboxImg.src = dataUrl;
    els.lightbox.classList.remove("hidden");
  });
  parent.appendChild(img);
}

function createNotificationCard(item) {
  const card = document.createElement("article");
  card.className = `notif-card${item.dismissed_at ? " dismissed" : ""}`;
  card.setAttribute("role", "listitem");

  const iconEl = document.createElement("div");
  iconEl.className = "app-icon";
  iconEl.textContent = (item.app_name || "?").slice(0, 1).toUpperCase();
  card.appendChild(iconEl);
  if (item.icon_sha256) {
    loadIcon(item.icon_sha256, iconEl);
  }

  const main = document.createElement("div");
  main.className = "notif-main";

  const meta = document.createElement("div");
  meta.className = "notif-meta";

  const appName = document.createElement("span");
  appName.className = "app-name";
  appName.textContent = item.app_name;
  meta.appendChild(appName);

  for (const dev of item.sender_devices || []) {
    const pill = document.createElement("span");
    pill.className = "device-pill";
    pill.textContent = dev;
    meta.appendChild(pill);
  }

  const time = document.createElement("span");
  time.className = "notif-time";
  time.textContent = formatRelativeTime(item.posted_at);
  meta.appendChild(time);
  main.appendChild(meta);

  if (item.title) {
    const title = document.createElement("div");
    title.className = "notif-title";
    title.textContent = item.title;
    main.appendChild(title);
  }

  if (item.body) {
    const body = document.createElement("div");
    body.className = "notif-body";
    body.textContent = item.body;
    main.appendChild(body);
  }

  if (item.attachment_path) {
    const thumbSlot = document.createElement("div");
    main.appendChild(thumbSlot);
    loadAttachment(item.id, thumbSlot);
  }

  if (!item.dismissed_at) {
    const actions = document.createElement("div");
    actions.className = "notif-actions";
    const btn = document.createElement("button");
    btn.className = "dismiss-btn";
    btn.textContent = "Dismiss";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await invoke("dismiss_notification", { rowId: item.id });
        await refreshAll();
      } catch {
        btn.disabled = false;
      }
    });
    actions.appendChild(btn);
    main.appendChild(actions);
  }

  card.appendChild(main);
  return card;
}

async function refreshFeed() {
  if (!appState || !appState.paired) return;
  const reqSeq = ++feedRequestSeq;
  const query = els.searchInput.value.trim();
  const items = await invoke("list_notifications", { query: query || null });
  if (reqSeq !== feedRequestSeq) return;
  const active = items.filter((n) => n.dismissed_at == null);
  const dismissed = items.filter((n) => n.dismissed_at != null);

  els.feedList.textContent = "";

  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const strong = document.createElement("strong");
    strong.textContent = query ? "No matching notifications" : "All caught up";
    const sub = document.createElement("div");
    sub.textContent = query
      ? "Try a different keyword."
      : "Incoming phone notifications will appear here.";
    empty.append(strong, sub);
    els.feedList.appendChild(empty);
    return;
  }

  if (active.length > 0) {
    const h = document.createElement("div");
    h.className = "section-heading";
    h.textContent = `Active (${active.length})`;
    els.feedList.appendChild(h);
    for (const item of active) {
      els.feedList.appendChild(createNotificationCard(item));
    }
  }

  if (dismissed.length > 0) {
    const h = document.createElement("div");
    h.className = "section-heading";
    h.textContent = `Dismissed (${dismissed.length})`;
    els.feedList.appendChild(h);
    for (const item of dismissed) {
      els.feedList.appendChild(createNotificationCard(item));
    }
  }
}

async function refreshAll() {
  await refreshState();
  await refreshFeed();
}

function showPairError(msg) {
  els.pairError.textContent = msg;
  els.pairError.classList.toggle("hidden", !msg);
}

function hideReplaceConfirm() {
  pendingReplaceUri = null;
  els.pairConfirmReplace.classList.add("hidden");
}

async function submitPairingUri(uri, forceReplace = false) {
  showPairError("");
  hideReplaceConfirm();
  const trimmed = (uri || "").trim();
  if (!trimmed) {
    showPairError("Paste an allnotify://pair URI or drop a QR code image.");
    return;
  }
  els.btnPairSubmit.disabled = true;
  try {
    appState = await invoke("pair_with_uri", { uri: trimmed, forceReplace });
    els.pairUriInput.value = "";
    showingSettings = false;
    showingRepair = false;
    renderHeaderAndViews();
    await refreshFeed();
  } catch (err) {
    const msg = String(err);
    if (msg === "CONFIRM_REPLACE") {
      pendingReplaceUri = trimmed;
      els.pairConfirmReplace.classList.remove("hidden");
    } else {
      showPairError(msg);
    }
  } finally {
    els.btnPairSubmit.disabled = false;
  }
}

async function handleQrFile(file) {
  if (!file) return;
  showPairError("");
  if (file.size > MAX_QR_IMAGE_BYTES) {
    showPairError("QR image exceeds 10 MB limit.");
    return;
  }
  try {
    const buf = await file.arrayBuffer();
    const bytes = Array.from(new Uint8Array(buf));
    const decodedUri = await invoke("decode_qr_image", { bytes });
    els.pairUriInput.value = decodedUri;
    await submitPairingUri(decodedUri);
  } catch (err) {
    showPairError(String(err));
  }
}

// ---- Event Wiring ----

els.btnPairSubmit.addEventListener("click", () => submitPairingUri(els.pairUriInput.value, false));
els.btnConfirmReplace.addEventListener("click", () => {
  if (pendingReplaceUri) submitPairingUri(pendingReplaceUri, true);
});
els.btnCancelReplace.addEventListener("click", () => hideReplaceConfirm());
els.btnPairCancel.addEventListener("click", () => {
  hideReplaceConfirm();
  showPairError("");
  showingRepair = false;
  renderHeaderAndViews();
});

els.btnOpenRepair.addEventListener("click", () => {
  hideReplaceConfirm();
  showPairError("");
  showingRepair = true;
  renderHeaderAndViews();
});

els.btnOpenAddDevice.addEventListener("click", () => {
  showingAddDevice = true;
  els.addDevError.classList.add("hidden");
  els.addDeviceQrCard.classList.add("hidden");
  els.addDeviceFormCard.classList.remove("hidden");
  renderHeaderAndViews();
  els.addDevName.focus();
});

els.btnBackSettings.addEventListener("click", () => {
  exitAddDeviceView();
  renderHeaderAndViews();
});

function showAddDevError(msg) {
  els.addDevError.textContent = msg;
  els.addDevError.classList.toggle("hidden", !msg);
}

els.btnGenerateQr.addEventListener("click", async () => {
  showAddDevError("");
  const name = els.addDevName.value.trim();
  if (!name) {
    showAddDevError("Enter a device name.");
    return;
  }
  els.btnGenerateQr.disabled = true;
  try {
    const res = await invoke("create_add_device_qr", {
      name,
      platform: els.addDevPlatform.value,
    });
    activeAddCode = res;
    els.addQrTitle.textContent = `${res.name} (${res.platform})`;
    els.addQrStatus.textContent = "Pending";
    els.addQrImg.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(res.qr_svg);
    els.addQrUri.value = res.pairing_uri;
    els.addDeviceFormCard.classList.add("hidden");
    els.addDeviceQrCard.classList.remove("hidden");
    setContentProtection(true);

    stopAddDeviceTimers();
    const tick = () => {
      if (!activeAddCode) return;
      const rem = Math.max(0, Math.floor((activeAddCode.expires_at - Date.now()) / 1000));
      const m = Math.floor(rem / 60);
      const s = String(rem % 60).padStart(2, "0");
      els.addQrCountdown.textContent = rem > 0 ? `Expires in ${m}:${s}` : "Expired";
      if (rem === 0) {
        els.addQrStatus.textContent = "Expired";
        stopAddDeviceTimers();
      }
    };
    tick();
    addCountdownTimer = setInterval(tick, 1000);

    addPollTimer = setInterval(async () => {
      if (!activeAddCode) return;
      try {
        const list = await invoke("list_my_pairing_codes");
        const found = list.find((item) => item.code_id === activeAddCode.code_id);
        if (!found) return;
        if (found.status === "claimed") {
          els.addQrStatus.textContent = "Claimed \u2713";
          els.addQrCountdown.textContent = "Device paired!";
          stopAddDeviceTimers();
        } else if (found.status === "expired" || found.status === "cancelled") {
          els.addQrStatus.textContent = found.status === "cancelled" ? "Cancelled" : "Expired";
          stopAddDeviceTimers();
        }
      } catch {
        // Ignore transient polling failures
      }
    }, 3000);
  } catch (err) {
    showAddDevError(String(err));
  } finally {
    els.btnGenerateQr.disabled = false;
  }
});

els.btnCopyAddUri.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(els.addQrUri.value);
    els.addQrFeedback.textContent = "Pairing link copied.";
    els.addQrFeedback.classList.remove("hidden");
    clearTimeout(addQrFeedbackTimer);
    addQrFeedbackTimer = setTimeout(() => els.addQrFeedback.classList.add("hidden"), 2500);
  } catch {
    els.addQrUri.select();
  }
});

els.btnAddAnother.addEventListener("click", () => {
  stopAddDeviceTimers();
  clearTimeout(addQrFeedbackTimer);
  activeAddCode = null;
  els.addDevName.value = "";
  els.addQrImg.removeAttribute("src");
  els.addQrUri.value = "";
  els.addQrFeedback.classList.add("hidden");
  els.addDeviceQrCard.classList.add("hidden");
  els.addDeviceFormCard.classList.remove("hidden");
  setContentProtection(false);
});

function openQrFilePicker() {
  // Fire-and-forget before synchronous .click() so WebKit/WebView2 preserves user activation.
  invoke("set_file_dialog_open", { open: true }).catch(() => {});
  els.qrFileInput.click();
}

els.qrDropzone.addEventListener("click", () => {
  openQrFilePicker();
});
els.qrDropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    openQrFilePicker();
  }
});
els.qrFileInput.addEventListener("change", async () => {
  invoke("set_file_dialog_open", { open: false }).catch(() => {});
  const file = els.qrFileInput.files && els.qrFileInput.files[0];
  els.qrFileInput.value = "";
  if (file) await handleQrFile(file);
});
els.qrFileInput.addEventListener("cancel", () => {
  invoke("set_file_dialog_open", { open: false }).catch(() => {});
});
window.addEventListener("focus", () => {
  invoke("set_file_dialog_open", { open: false }).catch(() => {});
  if (showingAddDevice && activeAddCode) {
    setContentProtection(true);
  }
  if (appState && appState.paired && !showingSettings && !showingAddDevice && !showingRepair) {
    refreshFeed().catch(() => {});
  }
});

els.qrDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  els.qrDropzone.classList.add("dragover");
});
els.qrDropzone.addEventListener("dragleave", () => {
  els.qrDropzone.classList.remove("dragover");
});
els.qrDropzone.addEventListener("drop", async (e) => {
  e.preventDefault();
  els.qrDropzone.classList.remove("dragover");
  const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (file) await handleQrFile(file);
});

els.btnMute.addEventListener("click", async () => {
  if (!appState) return;
  await invoke("set_muted", { muted: !appState.muted });
  await refreshState();
});

els.btnClearAll.addEventListener("click", async () => {
  await invoke("dismiss_all_active");
  await refreshAll();
});

els.btnSettings.addEventListener("click", () => {
  if (showingAddDevice) exitAddDeviceView();
  showingRepair = false;
  showingSettings = !showingSettings;
  if (showingSettings) syncRetentionInputs();
  renderHeaderAndViews();
});
els.btnAuthSettings.addEventListener("click", () => {
  showingSettings = true;
  syncRetentionInputs();
  renderHeaderAndViews();
});
els.btnBackFeed.addEventListener("click", () => {
  showingSettings = false;
  renderHeaderAndViews();
});

els.searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(refreshFeed, 120);
});

els.toggleAutostart.addEventListener("change", async () => {
  try {
    await invoke("set_autostart", { enabled: els.toggleAutostart.checked });
  } catch (err) {
    els.toggleAutostart.checked = !els.toggleAutostart.checked;
    showSettingsFeedback(String(err));
  }
});

els.togglePrivacy.addEventListener("change", async () => {
  await invoke("set_privacy_mode", { enabled: els.togglePrivacy.checked });
  await refreshState();
});

function showSettingsFeedback(msg) {
  els.settingsFeedback.textContent = msg;
  els.settingsFeedback.classList.remove("hidden");
  clearTimeout(feedbackTimer);
  feedbackTimer = setTimeout(() => els.settingsFeedback.classList.add("hidden"), 2500);
}

els.btnSaveRetention.addEventListener("click", async () => {
  const days = parseInt(els.inputRetDays.value, 10) || 30;
  const maxRows = parseInt(els.inputRetRows.value, 10) || 5000;
  await invoke("set_retention", { days, maxRows });
  await refreshState();
  syncRetentionInputs();
  showSettingsFeedback("Retention saved & pruned.");
});

function wireTwoStepConfirm(button, key, defaultText, confirmText, action) {
  button.addEventListener("click", async () => {
    if (button.dataset.armed === "1") {
      clearTimeout(confirmTimers[key]);
      button.dataset.armed = "0";
      button.textContent = defaultText;
      await action();
    } else {
      button.dataset.armed = "1";
      button.textContent = confirmText;
      confirmTimers[key] = setTimeout(() => {
        button.dataset.armed = "0";
        button.textContent = defaultText;
      }, 3500);
    }
  });
}

wireTwoStepConfirm(
  els.btnClearHistory,
  "clearHistory",
  "Clear local history now",
  "Click again to permanently clear history",
  async () => {
    attachmentCache.clear();
    await invoke("clear_history");
    showSettingsFeedback("Local history cleared.");
    await refreshAll();
  }
);

wireTwoStepConfirm(
  els.btnUnpair,
  "unpair",
  "Unpair / Reset this device",
  "Click again to confirm unpair",
  async () => {
    iconCache.clear();
    attachmentCache.clear();
    appState = await invoke("unpair");
    showingSettings = false;
    renderHeaderAndViews();
  }
);

els.lightboxClose.addEventListener("click", () => {
  els.lightbox.classList.add("hidden");
  els.lightboxImg.src = "";
});
els.lightbox.addEventListener("click", (e) => {
  if (e.target === els.lightbox) {
    els.lightbox.classList.add("hidden");
    els.lightboxImg.src = "";
  }
});

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (!els.lightbox.classList.contains("hidden")) {
      els.lightbox.classList.add("hidden");
      els.lightboxImg.src = "";
    } else if (showingAddDevice) {
      exitAddDeviceView();
      renderHeaderAndViews();
    } else if (showingRepair) {
      hideReplaceConfirm();
      showingRepair = false;
      renderHeaderAndViews();
    } else if (showingSettings) {
      showingSettings = false;
      renderHeaderAndViews();
    }
  }
});

// Backend push events
listen("sync:status", () => refreshState());
listen("state:updated", () => refreshState());
listen("notifications:updated", () => refreshAll());

refreshAll();
