"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  records: [],
  sortKey: "path",
  sortDir: 1,
  scanEvents: null,
  scanStart: 0,
  scanTimer: null,
  scanPoll: null,
  facet: null,
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
    loadLaunchTools(); // tools/ghidra dir may have changed - refresh the right-click menu
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
    setPhase("Starting…");
    setProgress(0, 0, "");
    startScanClock(Date.now());
    openScanStream();
    st.textContent = "running";
  } catch (e) {
    st.textContent = "error: " + e.message;
    btn.disabled = false;
  }
});

function fmtDuration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return (h ? `${h}:${String(m).padStart(2, "0")}` : `${m}`) + `:${String(sec).padStart(2, "0")}`;
}

function startScanClock(startMs) {
  state.scanStart = startMs;
  clearInterval(state.scanTimer);
  const tick = () => ($("#scan-elapsed").textContent = fmtDuration(Date.now() - state.scanStart));
  tick();
  state.scanTimer = setInterval(tick, 1000);
}

function stopScanClock() {
  clearInterval(state.scanTimer);
  state.scanTimer = null;
  if (state.scanStart) $("#scan-elapsed").textContent = fmtDuration(Date.now() - state.scanStart);
}

function setPhase(text) {
  $("#scan-phase").textContent = text || "";
}

function setProgress(done, total, current) {
  $("#scan-count").textContent = `${done} / ${total}`;
  $("#scan-current").textContent = current || "";
  const pct = total > 0 ? (done / total) * 100 : 0;
  $("#scan-bar").style.width = pct + "%";
  // an indeterminate sweep while a phase runs with no per-file count yet
  $(".progressbar").classList.toggle("indeterminate", total === 0 && state.scanTimer != null);
}

function openScanStream() {
  if (state.scanEvents) state.scanEvents.close();
  const es = new EventSource("/api/scan/current/events");
  state.scanEvents = es;
  // Backstop: each scan gets a fresh event channel, so an early event can be
  // missed in the gap between "scan started" and "stream connected". Poll the
  // status a few times a minute to keep the phase/elapsed honest regardless.
  clearInterval(state.scanPoll);
  state.scanPoll = setInterval(async () => {
    if (!state.scanEvents) { clearInterval(state.scanPoll); return; }
    try {
      const s = await api("/api/scan/current");
      if (s.finished) return;
      if (s.total === 0) { setPhase(s.phase); setProgress(state.records.length, 0, ""); }
    } catch { /* transient */ }
  }, 3000);
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.kind === "phase") {
      setPhase(msg.phase);
      setProgress(state.records.length, 0, "");
    } else if (msg.kind === "progress") {
      upsertRecord(msg.record);
      setPhase("Scanning files");
      setProgress(msg.done, msg.total, msg.record.path);
      if (!$(".view[data-view='results']").hidden) renderResults();
    } else if (msg.kind === "complete") {
      clearInterval(state.scanPoll);
      setProgress(msg.done, msg.total, "");
      stopScanClock();
      setPhase(msg.error ? "Finished with an error" : "Finished");
      $("#scan-state").textContent = msg.error
        ? `finished with error: ${msg.error}`
        : `finished in ${$("#scan-elapsed").textContent}`;
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
    if (!s.finished) {
      // a scan is still running (page reload / reconnect) - reattach
      $("#scan-start").disabled = true;
      $("#scan-progress").hidden = false;
      setPhase(s.phase || "Scanning files");
      startScanClock(s.started ? Date.parse(s.started) : Date.now());
      setProgress(s.done || 0, s.total || 0, "");
      if (!state.scanEvents) openScanStream();
    } else {
      stopScanClock();
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

function setFacet(key) {
  state.facet = key && DASHBOARD_FACETS[key] ? key : null;
  const bar = $("#results-facet");
  if (state.facet) {
    $("#results-facet-label").textContent = `Showing: ${DASHBOARD_FACETS[state.facet].label}`;
    bar.hidden = false;
  } else {
    bar.hidden = true;
  }
}

function renderResults() {
  const q = $("#results-filter").value.toLowerCase().trim();
  const hideNsrl = $("#results-hide-nsrl").checked;
  const facetFn = state.facet ? DASHBOARD_FACETS[state.facet].fn : null;
  let rows = state.records.filter((r) => {
    if (hideNsrl && r.nsrlMatch) return false;
    if (facetFn && !facetFn(r)) return false;
    if (!q) return true;
    return (
      (r.path || "").toLowerCase().includes(q) ||
      (r.sha1 || "").toLowerCase().includes(q) ||
      (r.status || "").toLowerCase().includes(q) ||
      (r.reputationStatus || "").toLowerCase().includes(q) ||
      (r.yaraMatches || "").toLowerCase().includes(q) ||
      (r.yaraSeverity || "").toLowerCase().includes(q) ||
      (r.yaraAttackTechniques || "").toLowerCase().includes(q) ||
      (r.ssdeep || "").toLowerCase().includes(q) ||
      (r.signerName || "").toLowerCase().includes(q) ||
      (r.signatureStatus || "").toLowerCase().includes(q) ||
      (r.sourceArchive || "").toLowerCase().includes(q)
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
      const sig = r.signatureStatus || "";
      const sigClass = sig === "Valid" ? "good" : (sig === "HashMismatch" || sig === "NotTrusted") ? "bad" : "";
      const sigCell = sig && sig !== "NotSupportedFileFormat"
        ? `<span class="tag ${sigClass}" title="${escapeHtml(r.signerName || "")}">${sig}</span>`
        : "";
      const srcCell = r.sourceArchive
        ? `<span class="muted mono" title="${escapeHtml(r.sourceArchive)}">${escapeHtml(r.sourceArchive.split(/[\\/]/).pop())}</span>`
        : "";
      return `<tr data-path="${escapeHtml(r.path)}">
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
        <td>${sigCell}</td>
        <td>${nsrl}</td>
        <td>${rep}</td>
        <td>${srcCell}</td>
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

// ------------------------------------------------ quick-launch context menu
let launchTools = null;
async function loadLaunchTools() {
  try { launchTools = await api("/api/launch-tools"); } catch { launchTools = null; }
}

const ctx = $("#ctxmenu");
document.addEventListener("click", () => (ctx.hidden = true));
window.addEventListener("blur", () => (ctx.hidden = true));

$("#results-table tbody").addEventListener("contextmenu", async (ev) => {
  const tr = ev.target.closest("tr[data-path]");
  if (!tr) return;
  ev.preventDefault();
  const path = tr.dataset.path;
  if (!launchTools) {
    ctx.innerHTML = `<button disabled>Finding tools…</button>`;
    ctx.style.left = Math.min(ev.clientX, window.innerWidth - 240) + "px";
    ctx.style.top = ev.clientY + "px";
    ctx.hidden = false;
    await loadLaunchTools();
    if (!launchTools) { ctx.hidden = true; return; }
  }
  const items = [];
  for (const t of launchTools.tools || []) {
    items.push({
      label: t.path ? t.label : `${t.label} (not installed)`,
      disabled: !t.path,
      run: () => runLaunch(t, path),
    });
  }
  if (launchTools.ghidra?.available) {
    items.push({ label: "Ghidra headless analysis", run: () => ghidraLaunch(path) });
  }
  items.push({ sep: true });
  items.push({ label: "Export for AI analysis…", run: () => aiExport(path) });

  ctx.innerHTML = items
    .map((it, i) =>
      it.sep
        ? `<div class="ctx-sep"></div>`
        : `<button data-i="${i}"${it.disabled ? " disabled" : ""}>${escapeHtml(it.label)}</button>`
    )
    .join("");
  ctx.querySelectorAll("button[data-i]").forEach((b) =>
    b.addEventListener("click", () => {
      ctx.hidden = true;
      items[+b.dataset.i].run();
    })
  );
  const mx = Math.min(ev.clientX, window.innerWidth - 240);
  const my = Math.min(ev.clientY, window.innerHeight - ctx.scrollHeight - 10);
  ctx.style.left = mx + "px";
  ctx.style.top = my + "px";
  ctx.hidden = false;
});

async function runLaunch(tool, filePath) {
  if (tool.needsConfirm &&
      !confirm(`${tool.label} runs the selected binary. Only do this in an isolated analysis environment. Continue?`)) {
    return;
  }
  try {
    await api("/api/launch", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ toolId: tool.id, filePath }),
    });
  } catch (e) { alert("Launch failed: " + e.message); }
}

async function ghidraLaunch(filePath) {
  try {
    await api("/api/ghidra", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ filePath }),
    });
    alert("Ghidra headless analysis started — it runs for a few minutes. See the Logs tab.");
  } catch (e) { alert("Ghidra launch failed: " + e.message); }
}

async function aiExport(filePath) {
  try {
    const r = await api("/api/ai-export", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ filePath }),
    });
    $("#ai-modal-body").textContent = r.markdown;
    $("#ai-modal-paths").textContent = `Saved: ${r.markdownPath}  •  ${r.jsonPath}`;
    $("#ai-modal").showModal();
    $("#ai-copy").onclick = () => navigator.clipboard.writeText(r.markdown);
  } catch (e) { alert("Export failed: " + e.message); }
}
$("#ai-close")?.addEventListener("click", () => $("#ai-modal").close());

// ---------------------------------------------------------------- dashboard
// Each entry: label, a per-file predicate `fn` (used both to count the tile
// and to filter the Results grid when the tile is clicked), and optionally a
// distinct `count` when the headline number isn't just fn's match count.
const inSsdeepCluster = (x) => x.ssdeepClusterId >= 0 && x.ssdeepClusterSize >= 2;
const inImphashCluster = (x) => x.imphashClusterId >= 0 && x.imphashClusterSize >= 2;
const DASHBOARD_FACETS = {
  all:        { label: "All files", fn: () => true },
  completed:  { label: "Completed", fn: (x) => x.status === "Completed" },
  errors:     { label: "Errored files", fn: (x) => x.status === "Error" },
  nsrl:       { label: "NSRL known-good", fn: (x) => !!x.nsrlMatch },
  knownBad:   { label: "Known-bad (blocklist)", fn: (x) => x.reputationStatus === "KnownBad" },
  highEntropy:{ label: "Entropy ≥ 7.5", fn: (x) => x.entropy >= 7.5 },
  imphash:    { label: "Has an imphash", fn: (x) => !!x.imphash },
  yara:       { label: "YARA hits", fn: (x) => x.yaraHitCount > 0 },
  sevCritical:{ label: "YARA severity: Critical", fn: (x) => x.yaraHitCount > 0 && x.yaraSeverity === "Critical" },
  sevHigh:    { label: "YARA severity: High", fn: (x) => x.yaraHitCount > 0 && x.yaraSeverity === "High" },
  sevMedium:  { label: "YARA severity: Medium", fn: (x) => x.yaraHitCount > 0 && x.yaraSeverity === "Medium" },
  sevLow:     { label: "YARA severity: Low", fn: (x) => x.yaraHitCount > 0 && x.yaraSeverity === "Low" },
  capaEligible:{ label: "capa-eligible", fn: (x) => !!x.capaEligible },
  capaHits:   { label: "Files with capa detections", fn: (x) => x.capaDetectionCount > 0 },
  capaDet:    { label: "Files with capa detections", fn: (x) => x.capaDetectionCount > 0,
                count: (r) => r.reduce((n, x) => n + (x.capaDetectionCount || 0), 0) },
  iocs:       { label: "Files with IOCs", fn: (x) => x.iocCount > 0 },
  attack:     { label: "ATT&CK-mapped", fn: (x) => !!x.yaraAttackTechniques },
  ssdeep:     { label: "In an SSDEEP cluster", fn: inSsdeepCluster,
                count: (r) => new Set(r.filter(inSsdeepCluster).map((x) => x.ssdeepClusterId)).size },
  highSim:    { label: "≥ 85% similar to another file", fn: (x) => !!x.ssdeepHasHighSimilarity },
  imphashClustered: { label: "In an imphash cluster", fn: inImphashCluster },
  sigValid:   { label: "Valid signature", fn: (x) => x.signatureStatus === "Valid" },
  sigProblem: { label: "Signature problem", fn: (x) => x.signatureStatus === "HashMismatch" || x.signatureStatus === "NotTrusted" },
  fromArchive:{ label: "Extracted from an archive", fn: (x) => !!x.sourceArchive },
  escalated:  { label: "Disposition: Escalated", fn: (x) => x.disposition === "Escalated" },
};

// tile display order: [facet key, tile label]
const DASHBOARD_TILES = [
  ["all", "Files"], ["completed", "Completed"], ["errors", "Errors"],
  ["nsrl", "NSRL known-good"], ["knownBad", "Known-bad"], ["highEntropy", "Entropy ≥ 7.5"],
  ["imphash", "Have imphash"], ["yara", "YARA hits"],
  ["sevCritical", "Critical"], ["sevHigh", "High"], ["sevMedium", "Medium"], ["sevLow", "Low"],
  ["capaEligible", "capa-eligible"], ["capaHits", "capa hits"], ["capaDet", "capa detections"],
  ["iocs", "Files with IOCs"], ["attack", "ATT&CK mapped"],
  ["ssdeep", "SSDEEP clusters"], ["highSim", "Files ≥ 85% sim"], ["imphashClustered", "Imphash clustered"],
  ["sigValid", "Valid signature"], ["sigProblem", "Signature problem"],
  ["fromArchive", "From an archive"], ["escalated", "Escalated"],
];

function renderDashboard() {
  const r = state.records;
  $("#tiles").innerHTML = DASHBOARD_TILES.map(([key, label]) => {
    const f = DASHBOARD_FACETS[key];
    const n = f.count ? f.count(r) : r.filter(f.fn).length;
    return `<button class="tile" data-facet="${key}"${n ? "" : " disabled"}>
      <div class="n">${n}</div><div class="l">${label}</div></button>`;
  }).join("");
}

$("#tiles").addEventListener("click", (ev) => {
  const tile = ev.target.closest("button.tile[data-facet]");
  if (!tile || tile.disabled) return;
  setFacet(tile.dataset.facet);
  showView("results");
  renderResults();
});

$("#results-facet-clear").addEventListener("click", () => {
  setFacet(null);
  renderResults();
});

// ---------------------------------------------------------------- antivirus
$("#av-detect")?.addEventListener("click", async () => {
  const btn = $("#av-detect");
  const out = $("#av-status");
  btn.disabled = true;
  out.textContent = "Checking…";
  try {
    const r = await api("/api/av");
    if (!r.products.length) {
      out.textContent =
        "No known antivirus/EDR product found. On Windows this can mean Security Center " +
        "isn't available (e.g. Windows Server) or nothing is registered; on Linux it means " +
        "nothing on Ingot's known-product list was detected.";
    } else {
      out.innerHTML =
        `<div class="av-line"><b>Detected:</b> ${r.products.map((p) => escapeHtml(p.name)).join(", ")}</div>` +
        r.products
          .map((p) => `<div class="av-line">• ${escapeHtml(p.name)}: ${escapeHtml(p.guidance)}</div>`)
          .join("");
    }
    const canAuto = r.defenderPresent && r.os === "windows";
    $("#av-exclude").hidden = !canAuto;
  } catch (e) {
    out.textContent = "Detection failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});

$("#av-exclude")?.addEventListener("click", async () => {
  const folder = $("#set-src").value.trim();
  if (!folder) {
    $("#av-status").textContent = "Set a source directory first, then Save settings.";
    return;
  }
  if (!confirm(
    `This prompts for administrator approval and adds this folder to Windows Defender's ` +
    `scan exclusions:\n\n${folder}\n\nFiles there (including malware) will NOT be ` +
    `automatically flagged by Defender. Continue?`
  )) return;
  const btn = $("#av-exclude");
  btn.disabled = true;
  $("#av-status").textContent = "Waiting for UAC elevation — check for a prompt on screen…";
  try {
    const r = await api("/api/av/exclude", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ path: folder }),
    });
    $("#av-status").textContent = "Added to Defender exclusions: " + r.excluded;
  } catch (e) {
    $("#av-status").textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});

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
loadLaunchTools();
