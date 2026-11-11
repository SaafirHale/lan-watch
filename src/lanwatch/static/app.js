"use strict";

// Every value from the API may contain text taken from network packets, so
// nothing here uses innerHTML: elements are built and filled with textContent.

const csrf = document.querySelector('meta[name="csrf-token"]').content;
let state = null;
let filter = "all";
let privacy = false;
const expanded = new Set();

try { privacy = localStorage.getItem("lanwatch.privacy") === "1"; } catch (_) { /* storage blocked */ }

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function rel(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

function abs(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

async function load() {
  const res = await fetch(`/api/state?privacy=${privacy ? 1 : 0}`, { cache: "no-store" });
  state = await res.json();
  render();
}

async function post(id, action, body) {
  const res = await fetch(`/api/devices/${encodeURIComponent(id)}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body),
  });
  if (!res.ok) alert((await res.json()).error || "Request failed");
  await load();
}

function displayName(d) {
  return d.label || d.hostname || d.vendor || (d.randomized ? "Private-address device" : "Unknown device");
}

function renderStatus() {
  const box = document.getElementById("status");
  box.replaceChildren();
  const devices = state.devices;
  const unknown = devices.filter((d) => !d.known).length;
  const priv = devices.filter((d) => d.randomized).length;
  const lastRun = state.runs[0];
  const net = state.network;
  const stat = (k, v, cls = "", small = false) =>
    el("div", { class: `stat ${cls}` }, el("div", { class: "k" }, k), el("div", { class: `v ${small ? "small" : ""}` }, v));
  box.append(
    stat("Devices", String(devices.length)),
    stat("Unknown", String(unknown), unknown ? "alert" : ""),
    stat("Private MACs", String(priv)),
    stat("Confirmed network", net ? `${net.profile || net.interface} · ${net.cidr}` : "not confirmed", "", true),
    stat(
      "Last run",
      lastRun ? `${rel(lastRun.finished || lastRun.started)} · ${lastRun.mode} · ${lastRun.status}` : "none yet",
      lastRun && lastRun.status !== "ok" ? "alert" : "",
      true,
    ),
  );
}

function matches(d, q) {
  if (filter === "unknown" && d.known) return false;
  if (filter === "known" && !d.known) return false;
  if (filter === "private" && !d.randomized) return false;
  if (!q) return true;
  return [d.label, d.hostname, d.vendor, d.ip, d.mac, d.model_hint].some((v) => v && v.toLowerCase().includes(q));
}

function renderDevices() {
  const body = document.getElementById("device-rows");
  body.replaceChildren();
  const q = document.getElementById("search").value.trim().toLowerCase();
  const rows = state.devices.filter((d) => matches(d, q));
  document.getElementById("no-devices").hidden = state.devices.length > 0;

  for (const d of rows) {
    const key = d.id || d.mac;
    const statusCls = d.known ? "known" : d.randomized ? "private" : "unknown";
    const nameCell = el(
      "td", {},
      el("div", { class: "name" }, displayName(d),
        d.known ? el("span", { class: "badge known" }, "known") : el("span", { class: "badge unknown" }, "unknown"),
        d.randomized ? el("span", { class: "badge private", title: "Locally administered (randomised) MAC" }, "private MAC") : null),
      el("div", { class: "sub" },
        [displayName(d) === d.vendor ? null : d.vendor || (d.randomized ? "no vendor (random address)" : "vendor not in OUI list"),
         d.hostname && d.label ? d.hostname : null,
         d.model_hint].filter(Boolean).join(" · ")),
    );
    const actions = el("td", {}, el("div", { class: "actions" },
      d.id ? el("button", { class: `small ${d.known ? "" : "primary"}`, onclick: () => post(d.id, "known", { known: !d.known }) }, d.known ? "Unmark" : "Mark as known") : null,
      d.id ? el("button", { class: "small", onclick: (ev) => editLabel(ev, d) }, "Label") : null,
      el("button", { class: "small", "aria-expanded": expanded.has(key) ? "true" : "false", onclick: () => { expanded.has(key) ? expanded.delete(key) : expanded.add(key); renderDevices(); } }, "History"),
    ));
    body.append(el("tr", { class: "device" },
      el("td", {}, el("span", { class: `dot ${statusCls}`, title: statusCls })),
      nameCell,
      el("td", { class: "mono" }, d.ip || "—"),
      el("td", { class: "mono" }, d.mac),
      el("td", { title: abs(d.first_seen) }, rel(d.first_seen)),
      el("td", { title: abs(d.last_seen) }, rel(d.last_seen), el("div", { class: "sub" }, d.sources.join(", "))),
      actions,
    ));
    if (expanded.has(key)) {
      const hist = d.ip_history.map((h) => `${h.ip} (${abs(h.first_seen)} → ${abs(h.last_seen)})`).join("  ·  ") || "no IP history";
      body.append(el("tr", { class: "history" }, el("td", {}), el("td", { colspan: "6" }, `IP history: ${hist}. Name source: ${d.hostname_source || "none"}.`)));
    }
  }
}

function editLabel(ev, d) {
  const cell = ev.target.closest("tr").children[1];
  const input = el("input", { class: "label-input", value: d.label || "", maxlength: "80", "aria-label": "Device label" });
  const save = () => post(d.id, "label", { label: input.value });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); if (e.key === "Escape") render(); });
  input.addEventListener("blur", save);
  cell.replaceChildren(input);
  input.focus();
}

function renderTimeline() {
  const list = document.getElementById("timeline");
  list.replaceChildren();
  const items = [
    ...state.events.map((e) => ({ ts: e.ts, sev: e.severity, text: e.message })),
    ...state.runs.map((r) => ({
      ts: r.finished || r.started, sev: "run",
      text: r.status === "ok"
        ? `${r.mode} run: ${r.device_count ?? 0} devices, ${r.new_count ?? 0} new`
        : `${r.mode} run ${r.status}${r.note ? `: ${r.note}` : ""}`,
    })),
  ].sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, 120);
  if (!items.length) list.append(el("li", {}, el("span"), el("span", { class: "empty" }, "Nothing yet.")));
  for (const it of items) {
    list.append(el("li", {}, el("span", { class: `sev ${it.sev}` }),
      el("div", {}, el("div", { class: "msg" }, it.text), el("div", { class: "when", title: abs(it.ts) }, `${rel(it.ts)} · ${abs(it.ts)}`))));
  }
}

function render() {
  const btn = document.getElementById("privacy");
  btn.setAttribute("aria-pressed", privacy ? "true" : "false");
  renderStatus();
  renderDevices();
  renderTimeline();
}

document.getElementById("refresh").addEventListener("click", load);
document.getElementById("privacy").addEventListener("click", () => {
  privacy = !privacy;
  try { localStorage.setItem("lanwatch.privacy", privacy ? "1" : "0"); } catch (_) { /* storage blocked */ }
  load();
});
document.getElementById("search").addEventListener("input", renderDevices);
for (const chip of document.querySelectorAll(".chip")) {
  chip.addEventListener("click", () => {
    filter = chip.dataset.filter;
    document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
    renderDevices();
  });
}
if (new URLSearchParams(location.search).get("privacy") === "1") privacy = true;
load();
setInterval(load, 60000);
