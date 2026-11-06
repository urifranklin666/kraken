/* KRAKEN console — vanilla JS, no dependencies. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const state = {
    token: sessionStorage.getItem("kraken.token") || "",
    status: null,
    aps: [],
    clients: [],
    handshakes: [],
    events: [],
    history: [],
    es: null,
    esFailures: 0,
    lastStatus: 0,
    lastLists: 0,
    apDirty: false,
    busy: false,
    tokenPrompted: false,
    followLogs: true,
  };

  const hashToken = new URLSearchParams(location.hash.replace(/^#/, "")).get("token");
  if (hashToken) {
    state.token = hashToken;
    try { sessionStorage.setItem("kraken.token", hashToken); } catch { /* storage blocked */ }
    history.replaceState(null, "", location.pathname + location.search);
  }

  const CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
  const CHANNELS_2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

  /* ------------------------------------------------------------- utilities */
  const pad = (n) => String(n).padStart(2, "0");

  function fmtBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} B`;
    const units = ["KiB", "MiB", "GiB", "TiB"];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
    return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[i]}`;
  }

  function fmtUptime(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    const d = Math.floor(total / 86400);
    const h = Math.floor((total % 86400) / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    return d > 0 ? `${d}d ${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(h)}:${pad(m)}:${pad(s)}`;
  }

  function fmtClock(ts) {
    const date = new Date((Number(ts) || Date.now() / 1000) * 1000);
    return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  }

  function fmtAgo(ts) {
    if (!ts) return "—";
    const diff = Math.max(0, Date.now() / 1000 - Number(ts));
    if (diff < 3) return "now";
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function fmtNum(value) {
    return new Intl.NumberFormat().format(Number(value) || 0);
  }

  function oui(mac) {
    return (mac || "").split(":").slice(0, 3).join(":").toUpperCase() || "—";
  }

  function setText(id, value) {
    const node = $(id);
    if (node) node.textContent = value == null || value === "" ? "—" : String(value);
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function cell(content, className) {
    const td = el("td", className);
    if (content instanceof Node) td.append(content);
    else td.textContent = content == null || content === "" ? "—" : String(content);
    return td;
  }

  function toast(message, kind = "info", title = "kraken") {
    const box = el("div", "toast");
    box.dataset.kind = kind;
    box.append(el("b", null, title), document.createTextNode(` — ${message}`));
    $("toasts").append(box);
    setTimeout(() => {
      box.classList.add("leaving");
      setTimeout(() => box.remove(), 240);
    }, kind === "error" ? 6500 : 4200);
  }

  function setConn(mode, label) {
    const node = $("conn");
    node.dataset.state = mode;
    $("conn-text").textContent = label || (mode === "on" ? "LIVE" : mode === "retry" ? "SYNC" : "DOWN");
  }

  /* ------------------------------------------------------------------- api */
  async function api(path, options = {}) {
    const headers = Object.assign({ Accept: "application/json" }, options.headers || {});
    if (state.token) headers["X-Kraken-Token"] = state.token;
    if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
    const response = await fetch(path, { cache: "no-store", ...options, headers });
    if (response.status === 401) {
      promptToken("this action needs the API token");
      throw new Error("token required");
    }
    let data = {};
    try { data = await response.json(); } catch { /* empty body */ }
    if (!response.ok || data.ok === false) {
      const detail = data.error || (Array.isArray(data.errors) && data.errors.join("; "));
      throw new Error(detail || `${response.status} ${response.statusText}`);
    }
    return data;
  }

  function promptToken(reason) {
    if (state.tokenPrompted) return;
    state.tokenPrompted = true;
    if (reason) $("token-error").textContent = reason;
    $("token-input").value = state.token || "";
    const dialog = $("token-dialog");
    if (!dialog.open) dialog.showModal();
    setTimeout(() => $("token-input").focus(), 40);
  }

  /* --------------------------------------------------------------- connect */
  function connect() {
    if (state.es) { state.es.close(); state.es = null; }
    const query = state.token ? `?token=${encodeURIComponent(state.token)}` : "";
    const source = new EventSource(`/api/events${query}`);
    state.es = source;

    source.addEventListener("open", () => {
      state.esFailures = 0;
      setConn("on", "LIVE");
    });

    source.addEventListener("message", (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === "status" && message.data) {
        state.esFailures = 0;
        setConn("on", "LIVE");
        applyStatus(message.data);
      }
    });

    source.addEventListener("error", async () => {
      state.esFailures += 1;
      if (state.esFailures < 2) { setConn("retry", "SYNC"); return; }
      setConn("off", "RETRY");
      try {
        const probe = await fetch("/api/status", {
          headers: state.token ? { "X-Kraken-Token": state.token } : {},
          cache: "no-store",
        });
        if (probe.status === 401) {
          source.close();
          promptToken("the dashboard token is missing or wrong");
          return;
        }
        if (probe.ok) {
          const data = await probe.json();
          applyStatus(data);
          setConn("retry", "SYNC");
        }
      } catch { /* daemon restarting */ }
    });
  }

  /* ---------------------------------------------------------------- status */
  function applyStatus(status) {
    state.status = status;
    state.lastStatus = Date.now() / 1000;

    setText("hostname", status.hostname || "kraken");
    setText("uptime", status.uptime_human || fmtUptime(status.uptime));
    setText("version", status.version ? `v${status.version}` : "—");
    setText("clock", fmtClock(status.time));
    setText("channels", `${status.channel || "—"} / ${status.capture?.hops ?? 0}`);

    const face = status.face || {};
    $("face").textContent = face.face || "(・_・)";
    setText("mood", face.mood || "—");
    setText("blurb", face.blurb || "");
    setText("epoch", face.epoch ?? 0);

    const mode = String(status.mode || "idle").toLowerCase();
    $$("#mode-switch button").forEach((button) => {
      button.dataset.active = String(button.dataset.mode === mode);
    });

    const counts = status.counts || {};
    setText("stat-aps", fmtNum(counts.aps));
    setText("stat-clients", fmtNum(counts.clients));
    setText("stat-handshakes", fmtNum(counts.handshakes));
    setText("stat-hs-sub", `${fmtNum(counts.verified)} verified`);
    const capture = status.capture || {};
    setText("stat-frames", fmtNum(capture.frames));
    setText("stat-eapol", `${fmtNum(capture.eapol)} eapol · ${fmtNum(capture.pmkid)} pmkid`);
    setText("stat-size", fmtBytes(capture.capture_size));
    setText("stat-file", capture.capture ? String(capture.capture).split("/").pop() : "no pcapng");
    setText("stat-deauth", fmtNum(capture.deauths));
    setText("stat-aggressive", status.aggressive ? "aggressive armed" : "passive");

    setText("kv-mode", mode.toUpperCase());
    setText("kv-monitor", capture.running ? `${capture.iface} · capturing` : `${capture.iface || "—"} · stopped`);
    setText("kv-channel", `${status.channel || "—"} / ${capture.hops ?? 0} hops`);
    setText("kv-ap", status.ap?.ssid || "—");
    setText("kv-apclients", (status.ap?.clients || []).length);
    setText("kv-mitm", status.mitm?.enabled ? "on" : "off");
    setText("kv-disk", fmtBytes(status.disk_free));

    setText("radio", capture.iface || "—");
    setText("uplink", status.uplink?.iface ? `${status.uplink.iface} ${status.uplink.ip || ""}`.trim() : "none");
    setText("auth-badge", status.authorized ? "AUTH ARMED" : "AUTH OFF");
    $("auth-badge").dataset.armed = String(Boolean(status.authorized));

    const warnings = status.warnings || [];
    const list = $("warnings");
    list.textContent = "";
    if (warnings.length === 0) {
      const li = el("li", "warn-none", "all systems nominal");
      list.append(li);
      $("warn-card").dataset.empty = "true";
    } else {
      warnings.forEach((warning) => list.append(el("li", null, warning)));
      $("warn-card").dataset.empty = "false";
    }

    applyAuth(status);
    applyApache(status);
    applyControls(status);

    const last = (status.events || []).slice(-1)[0];
    if (last) {
      $("ticker-text").textContent = `${last.kind}: ${last.message}`;
    }

    pushHistory(counts);
  }

  function applyAuth(status) {
    const authorized = Boolean(status.authorized);
    const allowed = Boolean(status.mitm?.allowed);
    $("auth-strip").dataset.state = authorized ? "on" : "off";
    const note = authorized
      ? "daemon armed with --authorized — interception and deauth are available on networks you own."
      : "daemon started without --authorized; MITM and deauth are locked.";
    $("auth-text").textContent = note;
    setText("mitm-note", !allowed ? "disabled in config" : authorized ? "ready" : "requires --authorized");
    setText("aggressive-note", !authorized ? "requires --authorized" : "targets must be whitelisted");

    $$('#controls [data-toggle="mitm"]').forEach((button) => {
      button.disabled = !allowed || !authorized;
    });
    $$('#controls [data-toggle="aggressive"]').forEach((button) => {
      button.disabled = !authorized;
    });
  }

  function applyControls(status) {
    const mitm = status.mitm || {};
    const mitmOn = Boolean(mitm.enabled);
    setText("mitm-pill", mitmOn ? "on" : "off");
    $("mitm-pill").dataset.on = String(mitmOn);
    $$('[data-control="mitm"]').forEach((card) => { card.dataset.armed = String(mitmOn); });

    const aggressive = Boolean(status.aggressive);
    setText("aggressive-pill", aggressive ? "armed" : "off");
    $("aggressive-pill").dataset.on = String(aggressive);
    $$('[data-control="aggressive"]').forEach((card) => { card.dataset.armed = String(aggressive); });

    $$("#mode-switch button").forEach((button) => {
      button.disabled = state.busy;
    });
  }

  function applyApache(status) {
    const ap = status.ap || {};
    setText("ap-state", ap.enabled ? "live" : "down");
    setText("ap-enabled", ap.enabled ? "running" : "stopped");
    setText("ap-iface", ap.iface || "—");
    setText("ap-portalip", ap.portal ? `${ap.portal_ip || "—"} → /portal` : "off");
    setText("ap-bandch", `${ap.band || "—"} GHz · ch ${ap.channel || "—"}`);
    setText("ap-sec", ap.secured ? "WPA2" : "open");
    setText("ap-uplink", ap.uplink?.iface ? `${ap.uplink.iface} ${ap.uplink.ip || ""}`.trim() : "—");

    const list = $("ap-clients");
    list.textContent = "";
    const clients = ap.clients || [];
    if (clients.length === 0) {
      list.append(el("li", "warn-none", "none associated"));
    } else {
      clients.forEach((client) => {
        const item = el("li");
        item.append(el("b", null, client.mac || client.ip || "?"), el("span", null,
          [client.ip, client.hostname, client.connected_s ? `${client.connected_s}s` : null].filter(Boolean).join(" · ") || "associated"));
        list.append(item);
      });
    }

    if (state.apDirty) return;
    const form = $("ap-form");
    if (form.contains(document.activeElement)) return;
    if (ap.ssid) $("ap-ssid").value = ap.ssid;
    $("ap-band").value = ap.band || "5";
    syncChannels(ap.channel);
    $("ap-portal").checked = Boolean(ap.portal);
    $("ap-passphrase").placeholder = ap.secured ? "unchanged" : "open network";
  }

  function syncChannels(selected) {
    const band = $("ap-band").value;
    const channels = band === "5" ? CHANNELS_5 : CHANNELS_2;
    const select = $("ap-channel");
    const current = Number(selected ?? select.value);
    select.textContent = "";
    channels.forEach((channel) => {
      const option = el("option", null, String(channel));
      option.value = String(channel);
      select.append(option);
    });
    select.value = String(channels.includes(current) ? current : channels[0]);
  }

  /* ----------------------------------------------------------------- lists */
  function filterRows(query, haystack) {
    const needle = query.trim().toLowerCase();
    if (!needle) return true;
    return haystack.toLowerCase().includes(needle);
  }

  function renderAps() {
    const body = $("aps-table").querySelector("tbody");
    const query = $("aps-filter").value;
    const rows = state.aps.filter((ap) => filterRows(query, `${ap.ssid} ${ap.bssid} ${ap.channel} ${ap.privacy}`));
    setText("aps-count", `${rows.length} / ${state.aps.length}`);
    body.textContent = "";
    if (rows.length === 0) {
      body.append(emptyRow(6, state.aps.length ? "no match for this filter" : "no networks yet — switch to hybrid or recon"));
      return;
    }
    rows.forEach((ap) => {
      const tr = el("tr");
      tr.append(
        cell(ap.ssid || "<hidden>", "ssid"),
        cell(ap.bssid, "bssid"),
        cell(ap.channel ?? "—", "mono-strong"),
        cell(rssiCell(ap.rssi)),
        cell(ap.privacy || "open"),
        cell(fmtAgo(ap.last_seen), "dim"),
      );
      body.append(tr);
    });
  }

  function rssiCell(rssi) {
    if (rssi == null) return el("span", "dim", "—");
    const wrap = el("span", "bar-rssi");
    const strength = Math.max(0, Math.min(100, Math.round(((Number(rssi) + 95) / 55) * 100)));
    const bar = el("i");
    bar.style.setProperty("--p", `${strength}%`);
    wrap.append(bar, el("span", null, `${rssi}`));
    return wrap;
  }

  function renderClients() {
    const body = $("clients-table").querySelector("tbody");
    const query = $("clients-filter").value;
    const rows = state.clients.filter((client) => filterRows(query, `${client.mac} ${client.bssid}`));
    setText("clients-count", `${rows.length} / ${state.clients.length}`);
    body.textContent = "";
    if (rows.length === 0) {
      body.append(emptyRow(5, state.clients.length ? "no match for this filter" : "no clients observed yet"));
      return;
    }
    rows.forEach((client) => {
      const tr = el("tr");
      tr.append(
        cell(client.mac, "mac"),
        cell(oui(client.mac), "dim"),
        cell(client.bssid, "bssid"),
        cell(rssiCell(client.rssi)),
        cell(fmtAgo(client.last_seen), "dim"),
      );
      body.append(tr);
    });
  }

  function renderHandshakes() {
    const body = $("captures-table").querySelector("tbody");
    setText("captures-count", `${state.handshakes.length}`);
    body.textContent = "";
    if (state.handshakes.length === 0) {
      body.append(emptyRow(8, "no EAPOL or PMKID material yet"));
      return;
    }
    state.handshakes.forEach((row) => {
      const tr = el("tr");
      const kind = el("span", `chip kind-${row.kind}`, row.kind || "eapol");
      const status = row.verified
        ? el("span", "chip ok", "verified")
        : el("span", "chip raw", "unverified");
      if (row.note && !row.verified) status.title = row.note;

      const actions = el("div", "row-actions");
      const verify = el("button", "mini-btn", "verify");
      verify.type = "button";
      verify.disabled = Boolean(row.verified);
      verify.addEventListener("click", () => verifyOne(row.id, verify));
      const download = el("button", "mini-btn", "download");
      download.type = "button";
      download.addEventListener("click", () => downloadCapture(row));
      actions.append(verify, download);

      tr.append(
        cell(`#${row.id}`, "mono-strong"),
        cell(fmtAgo(row.ts), "dim"),
        cell(kind),
        cell(row.bssid, "bssid"),
        cell(row.ssid || "<hidden>", "ssid"),
        cell(fmtBytes(row.size), "size"),
        cell(status),
        cell(actions),
      );
      body.append(tr);
    });
  }

  function emptyRow(colspan, message) {
    const tr = el("tr", "empty");
    const td = el("td", null, message);
    td.colSpan = colspan;
    tr.append(td);
    return tr;
  }

  function renderEvents() {
    const log = $("event-log");
    const shouldFollow = state.followLogs && $("logs-follow")?.checked;
    log.textContent = "";
    const events = state.events.slice(-120);
    if (events.length === 0) {
      log.append(el("div", "event", "no events yet"));
      return;
    }
    events.forEach((event) => {
      const row = el("div", "event");
      row.dataset.level = event.level || "info";
      row.append(
        el("time", null, fmtClock(event.ts)),
        el("span", "kind", event.kind || "system"),
        el("span", "msg", event.message || ""),
      );
      log.append(row);
    });
    if (shouldFollow) log.scrollTop = log.scrollHeight;
  }

  /* ----------------------------------------------------------------- chart */
  function pushHistory(counts) {
    const now = Date.now() / 1000;
    const last = state.history[state.history.length - 1];
    if (last && now - last.t < 1.7) {
      last.aps = counts.aps || 0;
      last.clients = counts.clients || 0;
      last.hs = counts.handshakes || 0;
      return;
    }
    state.history.push({
      t: now,
      aps: counts.aps || 0,
      clients: counts.clients || 0,
      hs: counts.handshakes || 0,
    });
    if (state.history.length > 120) state.history.shift();
    drawChart();
  }

  function drawChart() {
    const canvas = $("chart");
    if (!canvas) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(240, rect.width);
    const height = Math.max(120, rect.height || 176);
    if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const padL = 30;
    const padR = 8;
    const padT = 10;
    const padB = 18;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;
    const data = state.history;

    ctx.strokeStyle = "rgba(122,162,247,0.13)";
    ctx.lineWidth = 1;
    ctx.font = "9px ui-monospace, monospace";
    ctx.fillStyle = "#3b4261";

    const maxValue = Math.max(4, ...data.map((point) => Math.max(point.aps, point.clients, point.hs * 4)));
    const steps = 4;
    for (let i = 0; i <= steps; i += 1) {
      const y = padT + (plotH * i) / steps;
      ctx.beginPath();
      ctx.moveTo(padL, y + 0.5);
      ctx.lineTo(width - padR, y + 0.5);
      ctx.stroke();
      const label = Math.round(maxValue - (maxValue * i) / steps);
      ctx.fillText(String(label), 4, y + 3);
    }

    ctx.fillStyle = "#3b4261";
    ctx.fillText("time →", width - padR - 34, height - 5);

    if (data.length < 2) {
      setText("chart-empty", "collecting samples…");
      setText("chart-range", "—");
      return;
    }

    const x = (index) => padL + (plotW * index) / Math.max(1, data.length - 1);
    const y = (value) => padT + plotH - (plotH * Math.min(value, maxValue)) / maxValue;

    const series = [
      { key: "aps", color: "#7dcfff", scale: 1, fill: "rgba(125,207,255,0.13)" },
      { key: "clients", color: "#bb9af7", scale: 1, fill: "rgba(187,154,247,0.10)" },
      { key: "hs", color: "#9ece6a", scale: 4, fill: "rgba(158,206,106,0.10)" },
    ];

    series.forEach((line) => {
      ctx.beginPath();
      data.forEach((point, index) => {
        const px = x(index);
        const py = y(point[line.key] * line.scale);
        if (index === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      });
      ctx.lineTo(x(data.length - 1), padT + plotH);
      ctx.lineTo(x(0), padT + plotH);
      ctx.closePath();
      ctx.fillStyle = line.fill;
      ctx.fill();

      ctx.beginPath();
      data.forEach((point, index) => {
        const px = x(index);
        const py = y(point[line.key] * line.scale);
        if (index === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      });
      ctx.strokeStyle = line.color;
      ctx.lineWidth = 1.6;
      ctx.shadowColor = line.color;
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;
    });

    const last = data[data.length - 1];
    ctx.beginPath();
    ctx.arc(x(data.length - 1), y(last.aps), 2.6, 0, Math.PI * 2);
    ctx.fillStyle = "#7dcfff";
    ctx.fill();

    const span = Math.round((data[data.length - 1].t - data[0].t) / 60);
    setText("chart-empty", `${data.length} samples · aps ${last.aps} · clients ${last.clients}`);
    setText("chart-range", `last ${span < 1 ? "<1" : span}m`);
  }

  /* --------------------------------------------------------------- actions */
  async function setMode(mode) {
    if (state.busy) return;
    state.busy = true;
    $$("#mode-switch button").forEach((button) => { button.disabled = true; });
    try {
      const result = await api("/api/mode", { method: "POST", body: JSON.stringify({ mode }) });
      if (result.errors && result.errors.length) {
        result.errors.forEach((error) => toast(error, "warn", "mode"));
      }
      toast(`mode → ${result.mode}`, "ok", "mode");
      await refreshStatus();
      await refreshLists(true);
    } catch (error) {
      toast(error.message, "error", "mode");
    } finally {
      state.busy = false;
      $$("#mode-switch button").forEach((button) => { button.disabled = false; });
    }
  }

  async function applyAp(event) {
    event.preventDefault();
    const payload = {
      ssid: $("ap-ssid").value.trim(),
      band: $("ap-band").value,
      channel: Number($("ap-channel").value),
      portal: $("ap-portal").checked,
    };
    const passphrase = $("ap-passphrase").value;
    if (passphrase) payload.passphrase = passphrase;
    if (!payload.ssid) { toast("ssid cannot be empty", "warn", "access point"); return; }
    const submit = event.target.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      const result = await api("/api/ap", { method: "POST", body: JSON.stringify(payload) });
      state.apDirty = false;
      $("ap-passphrase").value = "";
      toast(`AP ${result.ap?.ssid} on ${result.ap?.band} GHz ch ${result.ap?.channel}`, "ok", "access point");
      await refreshStatus();
    } catch (error) {
      toast(error.message, "error", "access point");
    } finally {
      submit.disabled = false;
    }
  }

  async function toggle(name, enabled) {
    try {
      const result = await api(`/api/${name}`, { method: "POST", body: JSON.stringify({ enabled }) });
      toast(`${name} ${enabled ? "armed" : "disarmed"}`, enabled ? "warn" : "ok", "controls");
      applyControls({ ...(state.status || {}), mitm: result.mitm || state.status?.mitm, aggressive: result.aggressive ?? state.status?.aggressive });
      await refreshStatus();
    } catch (error) {
      toast(error.message, "error", name);
    }
  }

  async function panic() {
    if (!window.confirm("Stop the AP, monitor capture and interception?")) return;
    try {
      await api("/api/panic", { method: "POST", body: "{}" });
      toast("everything stopped", "warn", "panic");
      await refreshStatus();
    } catch (error) {
      toast(error.message, "error", "panic");
    }
  }

  async function verifyOne(id, button) {
    if (button) { button.disabled = true; button.textContent = "…"; }
    try {
      const result = await api("/api/verify", { method: "POST", body: JSON.stringify({ id }) });
      toast(result.verified ? `#${id} verified` : `#${id}: ${result.note || "no hashes"}`, result.verified ? "ok" : "warn", "verify");
      await refreshLists(true);
    } catch (error) {
      toast(error.message, "error", "verify");
      if (button) { button.disabled = false; button.textContent = "verify"; }
    }
  }

  async function verifyAll() {
    const pending = state.handshakes.filter((row) => !row.verified);
    if (pending.length === 0) { toast("nothing to verify", "info", "verify"); return; }
    const button = $("verify-all");
    button.disabled = true;
    let verified = 0;
    for (const row of pending) {
      try {
        const result = await api("/api/verify", { method: "POST", body: JSON.stringify({ id: row.id }) });
        if (result.verified) verified += 1;
      } catch (error) {
        toast(error.message, "error", `verify #${row.id}`);
        break;
      }
    }
    button.disabled = false;
    toast(`${verified}/${pending.length} verified`, verified ? "ok" : "warn", "verify");
    await refreshLists(true);
  }

  async function downloadCapture(row) {
    try {
      const headers = state.token ? { "X-Kraken-Token": state.token } : {};
      const response = await fetch(`/api/capture/${row.id}`, { headers, cache: "no-store" });
      if (response.status === 401) { promptToken("downloads need the API token"); return; }
      if (!response.ok) {
        let message = `${response.status} ${response.statusText}`;
        try { message = (await response.json()).error || message; } catch { /* ignore */ }
        throw new Error(message);
      }
      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = /filename="([^"]+)"/.exec(disposition);
      const name = match ? match[1] : `kraken-${row.id}-${row.kind}.pcapng`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = name;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
      toast(`downloaded ${name}`, "ok", "capture");
    } catch (error) {
      toast(error.message, "error", "capture");
    }
  }

  /* --------------------------------------------------------------- refresh */
  async function refreshStatus() {
    try {
      const status = await api("/api/status");
      applyStatus(status);
      return status;
    } catch (error) {
      if (!/token required/.test(error.message)) toast(error.message, "error", "telemetry");
      return null;
    }
  }

  async function refreshLists(force = false) {
    const now = Date.now() / 1000;
    if (!force && now - state.lastLists < 7) return;
    state.lastLists = now;
    try {
      const [aps, clients, handshakes] = await Promise.all([
        api("/api/aps?limit=500"),
        api("/api/clients?limit=500"),
        api("/api/handshakes?limit=150"),
      ]);
      state.aps = aps.aps || [];
      state.clients = clients.clients || [];
      state.handshakes = handshakes.handshakes || [];
      renderAps();
      renderClients();
      renderHandshakes();
    } catch (error) {
      if (!/token required/.test(error.message)) toast(error.message, "error", "lists");
    }
  }

  async function refreshLogs() {
    try {
      const result = await api("/api/logs?lines=120");
      $("raw-log").textContent = (result.logs || []).join("\n") || "empty log";
    } catch (error) {
      $("raw-log").textContent = `cannot read log: ${error.message}`;
    }
  }

  function applyEvents(events) {
    state.events = events || [];
    renderEvents();
  }

  /* ------------------------------------------------------------------- init */
  function bindUi() {
    $$("#mode-switch button").forEach((button) => {
      button.addEventListener("click", () => setMode(button.dataset.mode));
    });

    $("ap-form").addEventListener("submit", applyAp);
    $("ap-form").addEventListener("input", () => { state.apDirty = true; });
    $("ap-band").addEventListener("change", () => { state.apDirty = true; syncChannels(); });
    $("ap-refresh").addEventListener("click", async () => {
      state.apDirty = false;
      await refreshStatus();
      toast("form reloaded from daemon", "info", "access point");
    });

    $$("#controls [data-toggle]").forEach((button) => {
      button.addEventListener("click", () => toggle(button.dataset.toggle, button.dataset.value === "1"));
    });
    $("panic-btn").addEventListener("click", panic);

    $("aps-filter").addEventListener("input", renderAps);
    $("clients-filter").addEventListener("input", renderClients);
    $("verify-all").addEventListener("click", verifyAll);
    $("logs-refresh").addEventListener("click", refreshLogs);
    $("logs-follow").addEventListener("change", (event) => { state.followLogs = event.target.checked; });

    $("token-btn").addEventListener("click", () => { state.tokenPrompted = false; promptToken(); });

    $("token-dialog").querySelector("form").addEventListener("submit", (event) => {
      if (event.submitter?.value !== "save") return;
      event.preventDefault();
      const value = $("token-input").value.trim();
      if (!value) {
        $("token-error").textContent = "token cannot be empty";
        return;
      }
      state.token = value;
      sessionStorage.setItem("kraken.token", value);
      state.tokenPrompted = false;
      $("token-error").textContent = "";
      $("token-dialog").close("save");
      toast("token stored for this tab", "ok", "auth");
      connect();
      refreshStatus().then(() => refreshLists(true));
    });

    $("help-dialog").addEventListener("click", (event) => {
      if (event.target === $("help-dialog")) $("help-dialog").close();
    });
    $("help-close").addEventListener("click", () => $("help-dialog").close());

    document.addEventListener("keydown", (event) => {
      const tag = document.activeElement?.tagName;
      if (["INPUT", "SELECT", "TEXTAREA"].includes(tag)) return;
      if (event.key === "?" ) { $("help-dialog").showModal(); return; }
      if (event.key === "t" || event.key === "T") { state.tokenPrompted = false; promptToken(); return; }
      if (event.key === "r" || event.key === "R") { refreshStatus().then(() => refreshLists(true)); return; }
      const modes = { 1: "hybrid", 2: "recon", 3: "ap", 4: "idle" };
      if (modes[event.key]) setMode(modes[event.key]);
    });

    const sections = $$(".content section[id]");
    const links = new Map($$(".rail-nav a").map((link) => [link.getAttribute("href").slice(1), link]));
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        links.forEach((link) => link.classList.remove("active"));
        links.get(entry.target.id)?.classList.add("active");
      });
    }, { rootMargin: "-140px 0px -55% 0px", threshold: 0.01 });
    sections.forEach((section) => observer.observe(section));

    let resizeTimer = null;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(drawChart, 140);
    });

    window.addEventListener("beforeunload", () => state.es?.close());
  }

  async function boot() {
    bindUi();
    $("clock").textContent = fmtClock();
    setInterval(() => { $("clock").textContent = fmtClock(); }, 1000);

    const status = await refreshStatus();
    if (status) {
      applyEvents(status.events);
      await refreshLists(true);
      setConn("on", "LIVE");
    } else {
      setConn("retry", "SYNC");
    }
    connect();
    refreshLogs();

    setInterval(async () => {
      if (Date.now() / 1000 - state.lastStatus > 8) {
        await refreshStatus();
      }
      await refreshLists();
    }, 8000);

    setInterval(async () => {
      if (!state.status) return;
      try {
        const result = await api("/api/status");
        applyEvents(result.events);
      } catch { /* keep last view */ }
    }, 6000);

    setInterval(drawChart, 2000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
