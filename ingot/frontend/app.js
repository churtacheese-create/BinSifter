"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  records: [],
  sortKey: "path",
  sortDir: 1,
  scanEvents: null,
};

// ---------------------------------------------------------------- navigation
function showView(name) {
  $$(".view").forEach((v) => (v.hidden = v.dataset.view !== name));
  $$(".navlink").forEach((b) =>
    b.setAttribute("aria-current", b.dataset.view === name ? "true" : "false")
  );
  if (name === "results") renderResults();
  if (name === "dashboard") renderDashboard();
  if (name === "settings") loadSettings();
  if (name === "logs") $("#log-output").scrollTop = $("#log-output").scrollHeight;
  location.hash = name;
}
$$(".navlink").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));

// ---------------------------------------------------------------- helpers
async function api(path, opts) {
  const res = await fetch(path, opts);
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) throw new Error(typeof body === "string" ? body : res.statusText);
  return body;
}

function fmtEntropy(e) {
  return e >= 0 ? e.toFixed(3) : "";
}

// ---------------------------------------------------------------- health
async function pollHealth() {
  const badge = $("#health-badge");
  try {
    const h = await api("/api/health");
    badge.textContent = `${h.name} ${h.version}`;
    badge.className = "badge ok";
    $("#about-version").textContent = `${h.name} ${h.version}`;
  } catch {
    badge.textContent = "service offline";
    badge.className = "badge bad";
  }
}

// ---------------------------------------------------------------- settings
async function loadSettings() {
  try {
    const c = await api("/api/config");
    $("#set-src").value = c.srcDir || "";
    $("#set-nsrl").value = c.nsrlPath || "";
    $("#set-yara").value = c.yaraRules || "";
    $("#set-capa").value = c.capaRules || "";
    $("#set-tools").value = c.toolsDir || "";
    $("#set-ghidra").value = c.ghidraDir || "";
    $("#set-catalog").value = c.catalogDirectory || "";
    if (!$("#scan-src").value) $("#scan-src").value = c.srcDir || "";
    const dl = $("#fixed-locations");
    dl.innerHTML = "";
    for (const [k, v] of [
      ["Report directory", c.reportDirectory],
      ["MITRE ATT&CK data", c.attackDataPath],
      ["Blocklist", c.blocklistPath],
    ]) {
      dl.insertAdjacentHTML("beforeend", `<dt>${k}</dt><dd>${v || "—"}</dd>`);
    }
    await loadTools();
  } catch (e) {
    $("#settings-state").textContent = "could not load: " + e.message;
  }
}

async function loadTools() {
  const el = $("#tools-status");
  if (!el) return;
  const t = await api("/api/tools");
  el.innerHTML = "";
  for (const name of ["capa", "floss"]) {
    const info = t[name] || {};
    const status = info.available
      ? `<span class="tag good">installed</span> <span class="mono">${escapeHtml(info.path)}</span>`
      : `<span class="tag err">not installed</span> <button data-install="${name}">Download</button>`;
    el.insertAdjacentHTML("beforeend", `<dt>${name}</dt><dd>${status}</dd>`);
  }
  el.querySelectorAll("button[data-install]").forEach((b) =>
    b.addEventListener("click", async () => {
      b.disabled = true;
      b.textContent = "downloading… (see Logs)";
      try {
        await api(`/api/tools/install/${b.dataset.install}`, { method: "POST" });
        setTimeout(loadTools, 8000);
      } catch (e) {
        b.textContent = "failed: " + e.message;
        b.disabled = false;
      }
    })
  );
}

$("#settings-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const payload = Object.fromEntries([...fd.entries()].map(([k, v]) => [k, v.trim()]));
  const st = $("#settings-state");
  st.textContent = "saving…";
  try {
    await api("/api/config", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    st.textContent = "saved";
    if (payload.srcDir) $("#scan-src").value = payload.srcDir;
  } catch (e) {
    st.textContent = "error: " + e.message;
  }
});

// ---------------------------------------------------------------- scan
async function syncSrcDir() {
  const v = $("#scan-src").value.trim();
  const c = await api("/api/config");
  if ((c.srcDir || "") === v) return;
  await api("/api/config", {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      srcDir: v,
      nsrlPath: c.nsrlPath, yaraRules: c.yaraRules, capaRules: c.capaRules,
      toolsDir: c.toolsDir, ghidraDir: c.ghidraDir, catalogDirectory: c.catalogDirectory,
    }),
  });
}

$("#scan-start").addEventListener("click", async () => {
  const btn = $("#scan-start");
  const st = $("#scan-state");
  btn.disabled = true;
  st.textContent = "starting…";
  try {
    await syncSrcDir();
    await api("/api/scan", { method: "POST" });
    state.records = [];
    $("#scan-progress").hidden = false;
    $("#scan-reports").hidden = true;
    setProgress(0, 0, "");
    openScanStream();
    st.textContent = "running";
  } catch (e) {
    st.textContent = "error: " + e.message;
    btn.disabled = false;
  }
});

function setProgress(done, total, current) {
  $("#scan-count").textContent = `${done} / ${total}`;
  $("#scan-current").textContent = current || "";
  const pct = total > 0 ? (done / total) * 100 : 0;
  $("#scan-bar").style.width = pct + "%";
}

function openScanStream() {
  if (state.scanEvents) state.scanEvents.close();
  const es = new EventSource("/api/scan/current/events");
  state.scanEvents = es;
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.kind === "progress") {
      upsertRecord(msg.record);
      setProgress(msg.done, msg.total, msg.record.path);
      if (!$(".view[data-view='results']").hidden) renderResults();
    } else if (msg.kind === "complete") {
      setProgress(msg.done, msg.total, "");
      $("#scan-state").textContent = msg.error ? "finished with error: " + msg.error : "finished";
      $("#scan-start").disabled = false;
      es.close();
      state.scanEvents = null;
      loadScanStatus();
      loadReports();
    }
  };
  es.onerror = () => { /* browser auto-retries; complete event handles teardown */ };
}

function upsertRecord(rec) {
  const i = state.records.findIndex((r) => r.path === rec.path);
  if (i >= 0) state.records[i] = rec;
  else state.records.push(rec);
}

async function loadScanStatus() {
  try {
    const s = await api("/api/scan/current");
    if (Array.isArray(s.records) && s.records.length) {
      state.records = s.records;
      renderResults();
      renderDashboard();
    }
    if (s.finished && !s.error) {
      $("#scan-start").disabled = false;
    }
  } catch { /* no scan yet */ }
}

async function loadReports() {
  try {
    const s = await api("/api/scan/current");
    if (!s.reportPaths) return;
    const ul = $("#report-links");
    ul.innerHTML = "";
    for (const [kind, label] of [
      ["full", "Full triage report"],
      ["suspicious", "Suspicious / unknown (non-NSRL)"],
      ["yara", "YARA matches"],
      ["capa", "capa-compatible files"],
    ]) {
      ul.insertAdjacentHTML(
        "beforeend",
        `<li><a href="/api/scan/current/report/${kind}">${label}</a></li>`
      );
    }
    $("#scan-reports").hidden = false;
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------- results
$("#results-filter").addEventListener("input", renderResults);
$("#results-hide-nsrl").addEventListener("change", renderResults);
$$("#results-table th").forEach((th) =>
  th.addEventListener("click", () => {
    const k = th.dataset.sort;
    state.sortDir = state.sortKey === k ? -state.sortDir : 1;
    state.sortKey = k;
    renderResults();
  })
);

function renderResults() {
  const q = $("#results-filter").value.toLowerCase().trim();
  const hideNsrl = $("#results-hide-nsrl").checked;
  let rows = state.records.filter((r) => {
    if (hideNsrl && r.nsrlMatch) return false;
    if (!q) return true;
    return (
      (r.path || "").toLowerCase().includes(q) ||
      (r.sha1 || "").toLowerCase().includes(q) ||
      (r.status || "").toLowerCase().includes(q) ||
      (r.reputationStatus || "").toLowerCase().includes(q) ||
      (r.yaraMatches || "").toLowerCase().includes(q) ||
      (r.yaraSeverity || "").toLowerCase().includes(q) ||
      (r.yaraAttackTechniques || "").toLowerCase().includes(q) ||
      (r.ssdeep || "").toLowerCase().includes(q)
    );
  });

  const k = state.sortKey;
  rows.sort((a, b) => {
    let x = a[k], y = b[k];
    if (typeof x === "boolean") { x = x ? 1 : 0; y = y ? 1 : 0; }
    if (x == null) x = "";
    if (y == null) y = "";
    return (x < y ? -1 : x > y ? 1 : 0) * state.sortDir;
  });

  $("#results-count").textContent = `${rows.length} of ${state.records.length}`;
  const DISPOSITIONS = ["Untriaged", "Benign", "Suspicious", "Escalated"];
  const tbody = $("#results-table tbody");
  tbody.innerHTML = rows
    .slice(0, 2000)
    .map((r) => {
      const rep =
        r.reputationStatus === "KnownBad"
          ? `<span class="tag bad">KnownBad (${r.reputationSource})</span>`
          : r.reputationStatus || "";
      const nsrl = r.nsrlMatch ? `<span class="tag good">known-good</span>` : "";
      const status =
        r.status === "Error"
          ? `<span class="tag err">Error</span>`
          : r.status || "";
      const dispo = r.disposition || "Untriaged";
      const opts = DISPOSITIONS.map(
        (d) => `<option${d === dispo ? " selected" : ""}>${d}</option>`
      ).join("");
      const sel = r.sha1
        ? `<select class="dispo" data-sha1="${r.sha1}">${opts}</select>`
        : `<span class="muted">${dispo}</span>`;
      const sevClass = { Critical: "bad", High: "bad", Medium: "err", Low: "err" }[r.yaraSeverity] || "";
      const yaraCell = r.yaraHitCount > 0
        ? `<span title="${escapeHtml(r.yaraMatches || "")}">${r.yaraHitCount}</span>`
        : "";
      const sevCell = r.yaraHitCount > 0 && r.yaraSeverity !== "Unknown"
        ? `<span class="tag ${sevClass}">${r.yaraSeverity}${r.yaraSeverityScore >= 0 ? " " + r.yaraSeverityScore : ""}</span>`
        : "";
      const attackList = r.yaraAttackTechniques || "";
      const attackCell = attackList
        ? `<span class="muted" title="${escapeHtml(attackList)}">${attackList.split(";").length} tech.</span>`
        : "";
      let clusterCell = "";
      if (r.ssdeepClusterId >= 0 && r.ssdeepClusterSize >= 2) {
        const hs = r.ssdeepHasHighSimilarity ? ' <span class="tag bad">≥85%</span>' : "";
        clusterCell = `<span title="${escapeHtml(r.ssdeepMatches || "")}">S#${r.ssdeepClusterId} ×${r.ssdeepClusterSize}</span>${hs}`;
      } else if (r.imphashClusterId >= 0 && r.imphashClusterSize >= 2) {
        clusterCell = `<span class="muted">I#${r.imphashClusterId} ×${r.imphashClusterSize}</span>`;
      }
      let capaCell = "";
      if (r.capaDetectionCount > 0) {
        const fmt = r.capaShellcodeFormat ? ` (${r.capaShellcodeFormat})` : "";
        capaCell = `<span title="${escapeHtml(r.capaOutput || "")}">${r.capaDetectionCount}${fmt}</span>`;
      } else if (r.error && r.error.startsWith("capa")) {
        capaCell = `<span class="tag err" title="${escapeHtml(r.error)}">!</span>`;
      }
      const iocCell = r.iocCount > 0
        ? `<span class="tag bad" title="${escapeHtml(r.extractedIocs || "")}">${r.iocCount}</span>`
        : "";
      return `<tr>
        <td class="path" title="${escapeHtml(r.path)}">${escapeHtml(r.path)}</td>
        <td class="hash">${(r.sha1 || "").slice(0, 16)}</td>
        <td>${fmtEntropy(r.entropy)}</td>
        <td class="hash">${r.imphash || ""}</td>
        <td>${clusterCell}</td>
        <td>${yaraCell}</td>
        <td>${sevCell}</td>
        <td>${attackCell}</td>
        <td>${capaCell}</td>
        <td>${iocCell}</td>
        <td>${nsrl}</td>
        <td>${rep}</td>
        <td>${status}</td>
        <td>${sel}</td>
      </tr>`;
    })
    .join("");

  $$("#results-table select.dispo").forEach((sel) =>
    sel.addEventListener("change", async () => {
      const sha1 = sel.dataset.sha1;
      const disposition = sel.value;
      sel.disabled = true;
      try {
        await api("/api/disposition", {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ sha1, disposition }),
        });
        state.records.forEach((r) => {
          if (r.sha1 === sha1) r.disposition = disposition;
        });
      } catch (e) {
        sel.value = state.records.find((r) => r.sha1 === sha1)?.disposition || "Untriaged";
        alert("Could not save disposition: " + e.message);
      } finally {
        sel.disabled = false;
      }
    })
  );
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}

// ---------------------------------------------------------------- dashboard
function renderDashboard() {
  const r = state.records;
  const completed = r.filter((x) => x.status === "Completed").length;
  const errors = r.filter((x) => x.status === "Error").length;
  const nsrl = r.filter((x) => x.nsrlMatch).length;
  const knownBad = r.filter((x) => x.reputationStatus === "KnownBad").length;
  const highEntropy = r.filter((x) => x.entropy >= 7.5).length;
  const withImphash = r.filter((x) => x.imphash).length;
  const escalated = r.filter((x) => x.disposition === "Escalated").length;
  const yaraHits = r.filter((x) => x.yaraHitCount > 0).length;
  const sev = (s) => r.filter((x) => x.yaraHitCount > 0 && x.yaraSeverity === s).length;
  const capaEligible = r.filter((x) => x.capaEligible).length;
  const capaHits = r.reduce((n, x) => n + (x.capaDetectionCount > 0 ? 1 : 0), 0);
  const capaDetections = r.reduce((n, x) => n + (x.capaDetectionCount || 0), 0);
  const withIocs = r.filter((x) => x.iocCount > 0).length;
  const withAttack = r.filter((x) => x.yaraAttackTechniques).length;
  const ssdeepClusters = new Set(
    r.filter((x) => x.ssdeepClusterId >= 0 && x.ssdeepClusterSize >= 2).map((x) => x.ssdeepClusterId)
  ).size;
  const highSim = r.filter((x) => x.ssdeepHasHighSimilarity).length;
  const imphashClustered = r.filter((x) => x.imphashClusterId >= 0 && x.imphashClusterSize >= 2).length;
  const tiles = [
    ["Files", r.length],
    ["Completed", completed],
    ["Errors", errors],
    ["NSRL known-good", nsrl],
    ["Known-bad", knownBad],
    ["Entropy ≥ 7.5", highEntropy],
    ["Have imphash", withImphash],
    ["YARA hits", yaraHits],
    ["Critical", sev("Critical")],
    ["High", sev("High")],
    ["Medium", sev("Medium")],
    ["Low", sev("Low")],
    ["capa-eligible", capaEligible],
    ["capa hits", capaHits],
    ["capa detections", capaDetections],
    ["Files with IOCs", withIocs],
    ["ATT&CK mapped", withAttack],
    ["SSDEEP clusters", ssdeepClusters],
    ["Files ≥ 85% sim", highSim],
    ["Imphash clustered", imphashClustered],
    ["Escalated", escalated],
  ];
  $("#tiles").innerHTML = tiles
    .map(([l, n]) => `<div class="tile"><div class="n">${n}</div><div class="l">${l}</div></div>`)
    .join("");
}

// ---------------------------------------------------------------- logs
function openLogStream() {
  const es = new EventSource("/api/logs/events");
  const out = $("#log-output");
  es.onmessage = (ev) => {
    out.textContent += ev.data + "\n";
    if (out.textContent.length > 400000) out.textContent = out.textContent.slice(-300000);
    if ($("#logs-follow").checked) out.scrollTop = out.scrollHeight;
  };
}
$("#logs-clear").addEventListener("click", () => ($("#log-output").textContent = ""));

// ---------------------------------------------------------------- boot
showView(location.hash.replace("#", "") || "scan");
pollHealth();
setInterval(pollHealth, 10000);
loadSettings();
openLogStream();
loadScanStatus();
loadReports();
