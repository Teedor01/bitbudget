"use strict";
// ---- Pure helpers (unit-tested under Node) -------------------------------------------------
function fmtUsd(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "?";
  return (n < 0 ? "-" : "") + "$" + Math.abs(n).toLocaleString("en-US");
}
function fmtCount(n) {
  return (typeof n === "number" && Number.isFinite(n)) ? n.toLocaleString("en-US") : "?";
}
function shareOf(size, total) {
  if (!(total > 0) || typeof size !== "number") return 0;
  return Math.min(Math.max((size / total) * 100, 0), 100);
}
function barGeometry(lo, hi, domLo, domHi) {
  const span = domHi - domLo + 1;
  const left = ((lo - domLo) / span) * 100;
  const width = Math.max(((hi - lo + 1) / span) * 100, 0.6);
  return { leftPct: Math.min(Math.max(left, 0), 100), widthPct: Math.min(width, 100) };
}
function verdictText(resp, answer) {
  if (resp === "ANSWER") return answer ? "YES" : "NO";
  return resp;   // REFUSED | REJECTED | RETRY
}
function describeVerdict(resp, answer, threshold) {
  if (resp === "ANSWER") return (answer ? "YES: income is above " : "NO: income is at or below ") + fmtUsd(threshold);
  if (resp === "REFUSED") return "REFUSED: no answer was given";
  if (resp === "REJECTED") return "REJECTED: the request was not accepted";
  return "RETRY: the gate could not complete the request; ask again";
}
function shortDigest(d) {
  if (typeof d !== "string" || d.length < 20) return typeof d === "string" ? d : "?";
  return d.slice(0, 10) + "\u2026" + d.slice(-6);
}
function parseIntegerField(text) {
  const t = String(text).trim();
  if (!/^-?\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}

// ---- DOM wiring (browser only) -------------------------------------------------------------
if (typeof document !== "undefined") {
  const $ = (id) => document.getElementById(id);
  const DOM_LO = 0, DOM_HI = 999999;
  let session = null, ownerToken = null, busy = false, live = false;

  async function api(path, method, body, token) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers["X-Owner-Token"] = token;
    let res;
    try {
      res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) {
      throw new Error("Cannot reach the local server. Is it still running?");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { const err = new Error(data.error || ("request failed (" + res.status + ")")); err.status = res.status; throw err; }
    return data;
  }
  function cell(tr, text) { const td = document.createElement("td"); td.textContent = text; tr.appendChild(td); }
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  const range = (r) => fmtCount(r.size) + " candidates (" + fmtUsd(r.lo) + " to " + fmtUsd(r.hi) + ")";

  function syncControls() {
    $("create").disabled = busy; $("story-run").disabled = busy;
    $("ask").disabled = busy || !session; $("attack").disabled = busy || !session;
  }
  async function guarded(fn) {            // one request in flight at a time; a genuine local-request state, nothing more
    if (busy) return;
    busy = true; syncControls();
    try { await fn(); } finally { busy = false; syncControls(); }
  }

  // ---- 1. Story: numbers come from the engine via /api/demo-story ----
  function renderStory(d) {
    $("story-open").hidden = false; $("story-gated").hidden = false;
    const u = d.unrestricted;
    $("open-headline").textContent = u.queries + " questions \u2192 exactly " + fmtUsd(u.recovered_usd);
    $("open-seq").textContent = [fmtCount(d.domain_size)].concat(u.steps.map((s) => fmtCount(s.candidates))).join(" \u2192 ");
    const ol = $("gated-steps"); clear(ol);
    const floorPct = shareOf(d.floor, d.domain_size);
    function row(head, seesText, seesCls, size) {
      const li = el("li");
      li.appendChild(el("div", "head", head));
      const cols = el("div", "cols");
      cols.appendChild(el("span", "sees " + seesCls, seesText));
      cols.appendChild(el("span", "tracks", fmtCount(size) + " candidates left"));
      li.appendChild(cols);
      const track = el("div", "track"), fill = el("div", "fillbar"), line = el("div", "floorline");
      fill.style.width = Math.max(shareOf(size, d.domain_size), 0.6) + "%"; line.style.left = floorPct + "%";
      track.appendChild(fill); track.appendChild(line); li.appendChild(track); ol.appendChild(li);
    }
    row("Start", "no questions yet", "", d.domain_size);
    d.bit_budget.steps.forEach((s) => {
      const seen = s.verifier_sees;
      row("Step " + s.step + ": " + s.verifier_id + " asks \u201cincome above " + fmtUsd(s.threshold) + "?\u201d",
          "Verifier sees: " + seen, seen.toLowerCase(), s.candidates_after);
    });
    const b = d.bit_budget;
    $("gated-summary").textContent = "Floor " + (b.floor_held ? "held" : "VIOLATED") + ": " + fmtCount(b.final_candidates) +
      " candidates remain (floor " + fmtCount(d.floor) + "). From step " + b.first_refusal_step + " on, every further question is refused.";
  }
  async function loadStory() {
    $("story-status").textContent = "Loading the demo from the local engine\u2026";
    try { renderStory(await api("/api/demo-story", "GET")); $("story-status").textContent = ""; }
    catch (e) { $("story-status").textContent = "Could not load the demo: " + e.message; }
  }

  // ==VERIFIER-UI== (only what a verifier may see: its own question and the gate's reply)
  const verifierLog = [];
  function renderVerifierLog() {
    const tb = $("vlog").querySelector("tbody"); clear(tb);
    verifierLog.slice().reverse().forEach((e, i) => {
      const tr = el("tr");
      cell(tr, String(verifierLog.length - i)); cell(tr, e.verifier_id); cell(tr, fmtUsd(e.threshold));
      cell(tr, verdictText(e.response, e.answer)); tb.appendChild(tr);
    });
  }
  function renderVerdict(r) {
    const v = verdictText(r.response, r.answer);
    const box = $("verdict"); box.textContent = describeVerdict(r.response, r.answer, r.threshold) + (r.detail ? " " + r.detail : "");
    box.className = "verdict " + v.toLowerCase();
  }
  async function askAsVerifier(t) {
    const r = await api("/api/sessions/" + session + "/query", "POST", { verifier_id: $("verifier").value, threshold: t });
    verifierLog.push(r); renderVerdict(r); renderVerifierLog();
  }
  function resetVerifierUi(hint) {
    verifierLog.length = 0; renderVerifierLog(); $("verdict").textContent = ""; $("verdict").className = "verdict";
    $("verifier-hint").textContent = hint; $("verifier-hint").hidden = hint === "";
  }
  // ==END-VERIFIER-UI==

  // ---- Owner / auditor panel (requires the owner token) ----
  function renderOwner(v) {
    $("auditor-empty").hidden = true; $("owner-view").hidden = false;
    $("sid").textContent = v.session_id; $("secret").textContent = fmtUsd(v.owner_secret_usd);
    $("flo").textContent = fmtUsd(v.feasible.lo); $("fhi").textContent = fmtUsd(v.feasible.hi);
    $("fsize").textContent = fmtCount(v.feasible.size);
    $("floor").textContent = fmtUsd(v.floor) + (v.floor_holds ? " (holds)" : " (VIOLATED)");
    $("ver").textContent = String(v.anchor_version); $("adv").textContent = String(v.advantage_bits_display_only);
    const g = barGeometry(v.feasible.lo, v.feasible.hi, DOM_LO, DOM_HI);
    $("barfill").style.left = g.leftPct + "%"; $("barfill").style.width = g.widthPct + "%";
    const vt = $("vtable").querySelector("tbody"); clear(vt);
    Object.keys(v.verifiers).forEach((k) => { const tr = el("tr"), x = v.verifiers[k];
      cell(tr, k); cell(tr, String(x.informative_answers)); cell(tr, String(x.committed_requests)); vt.appendChild(tr); });
    const last = v.log.length ? v.log[v.log.length - 1].auditor_view : null;
    $("r-decision").textContent = last ? last.policy_decision + (last.reason !== "-" ? " (reason: " + last.reason + ")" : "") : "\u2013";
    $("r-range").textContent = last ? fmtCount(last.feasible_before.size) + " \u2192 " + fmtCount(last.feasible_after.size) : "\u2013";
    $("r-commit").textContent = last ? (last.committed === null ? "unknown (the chain could not be read after the gate answered)" : last.committed ? "yes, anchor version " + last.anchor_version_before + " \u2192 " + last.anchor_version_after : "no transition committed") : "\u2013";
    $("r-consistent").textContent = last ? (last.consistent_with_policy === null ? "n/a (write not confirmed yet)" : last.consistent_with_policy ? "yes" : "NO: mismatch (this is a bug)") : "\u2013";
    const lb = $("log").querySelector("tbody"); clear(lb);
    v.log.slice().reverse().forEach((e) => { const tr = el("tr");
      cell(tr, String(e.n)); cell(tr, e.verifier_id); cell(tr, fmtUsd(e.threshold));
      cell(tr, verdictText(e.verifier_view.response, e.verifier_view.answer));
      cell(tr, e.auditor_view.policy_decision + (e.auditor_view.reason !== "-" ? " (" + e.auditor_view.reason + ")" : ""));
      cell(tr, fmtCount(e.auditor_view.feasible_after.size)); lb.appendChild(tr); });
  }
  function dropSession(msg) {
    session = null; ownerToken = null;
    $("owner-view").hidden = true; $("auditor-empty").hidden = false; $("attack-result").hidden = true;
    resetVerifierUi("Session no longer exists (the server may have restarted). Create a new session.");
    $("owner-error").textContent = msg; syncControls();
  }
  async function refreshOwner() {
    if (!session || (live && !ownerToken)) return;
    try { renderOwner(await api("/api/sessions/" + session, "GET", undefined, ownerToken)); }
    catch (e) { if (e.status === 404) dropSession(e.message); else throw e; }
  }

  // ---- Live NEAR testnet mode: only when /api/mode says so; local mode never reaches these branches ----
  function renderChain(c) {
    $("chain-contract").textContent = c.contract + " (" + c.network + ")";
    $("chain-signer").textContent = c.signing_account;
    const h = c.head;
    $("chain-version").textContent = h ? String(h.version) : "unavailable";
    $("chain-digest").textContent = h ? h.digest : "\u2013";
    $("chain-scope").textContent = h ? h.scope_id : "\u2013";
    $("chain-time").textContent = c.read_at ? new Date(c.read_at * 1000).toISOString() : "\u2013";
    $("chain-status").textContent = h ? "Read at finality=final. This view is read-only." : (c.error || "unavailable");
    const box = $("chain-links"); clear(box);
    Object.keys(c.explorer || {}).forEach((k) => {
      const a = el("a", "", "Open " + k.replace(/_/g, " ") + " on NearBlocks (read-only)");
      a.href = c.explorer[k]; a.setAttribute("rel", "noopener noreferrer"); a.setAttribute("target", "_blank"); box.appendChild(a);
    });
    $("chain-verify").textContent = c.verify_with || "";
  }
  async function loadChain() {
    $("chain-status").textContent = "Reading the chain head from NEAR testnet\u2026";
    try { renderChain(await api("/api/chain", "GET")); }
    catch (e) { $("chain-status").textContent = "Could not read the chain head: " + e.message; }
  }
  async function detectMode() {
    let m;
    try { m = await api("/api/mode", "GET"); } catch (e) { return; }
    if (!m || m.mode !== "near-testnet") return;
    live = true; session = m.session_id;
    document.title = "Bit Budget: LIVE NEAR TESTNET";
    $("notice").hidden = true;                                   // the static local-simulation notice would be false here
    $("live-banner").textContent = m.notice; $("live-banner").hidden = false;
    $("create-form").hidden = true; $("token-form").hidden = false; $("chain-panel").hidden = false;
    $("attack").hidden = true; $("attack-error").textContent = "The adversarial demo is not available in live NEAR mode.";
    resetVerifierUi("Live NEAR testnet: each question is committed on chain by this server\u2019s signing account. An answer appears only after the commit is confirmed, which takes several seconds.");
    $("owner-error").textContent = "Owner view: paste the operator token printed on the server console.";
    syncControls(); await loadChain();
  }

  // ---- Wiring ----
  $("create-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    return guarded(async () => {
      $("owner-error").textContent = "";
      const income = parseIntegerField($("income").value);
      const kRaw = $("capK").value.trim(), rRaw = $("capR").value.trim();
      const K = kRaw === "" ? null : parseIntegerField(kRaw), R = rRaw === "" ? null : parseIntegerField(rRaw);
      if (income === null || income < DOM_LO || income > DOM_HI) { $("owner-error").textContent = "Income must be a whole number between 0 and 999,999."; return; }
      if ((kRaw !== "" && K === null) || (rRaw !== "" && R === null)) { $("owner-error").textContent = "K and R must be whole numbers or blank."; return; }
      try {
        const s = await api("/api/sessions", "POST", { income_usd: income, K: K, R: R });
        session = s.session_id; ownerToken = s.owner_token;
        resetVerifierUi(""); $("ask-error").textContent = ""; $("attack-result").hidden = true;
        await refreshOwner(); syncControls(); $("threshold").focus();
      } catch (e) { $("owner-error").textContent = e.message; }
    });
  });
  $("ask-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    return guarded(async () => {
      $("ask-error").textContent = "";
      if (!session) { $("ask-error").textContent = "Create a session first."; return; }
      const t = parseIntegerField($("threshold").value);
      if (t === null) { $("ask-error").textContent = "Threshold must be a whole number."; return; }
      try { await askAsVerifier(t); await refreshOwner(); if (live) await loadChain(); }
      catch (e) { if (e.status === 404) dropSession(e.message); else $("ask-error").textContent = e.message; }
    });
  });
  $("quick").addEventListener("click", (ev) => {
    const b = ev.target.closest("button");
    if (b && b.dataset.t) { $("threshold").value = b.dataset.t; $("threshold").focus(); }
  });
  $("attack").addEventListener("click", () => guarded(async () => {
    $("attack-error").textContent = "";
    try {
      const r = await api("/api/sessions/" + session + "/attack", "POST", { strategy: $("strategy").value }, ownerToken);
      $("attack-result").hidden = false;
      $("attack-base").textContent = "No accounting: the attacker recovered " + fmtUsd(r.baseline_stateless.recovered_usd) + " exactly in " + r.baseline_stateless.queries + " questions.";
      const g = r.gated;
      $("attack-gated").textContent = "Through the gate (" + g.requests_sent + " requests, " + g.answers_obtained + " answers): " + range(g.attacker_feasible) +
        " left. Floor " + fmtUsd(g.floor) + (g.floor_held ? " held" : " VIOLATED") + "; secret recovered: " + (g.secret_recovered ? "YES" : "no") + ".";
      const tb = $("steps").querySelector("tbody"); clear(tb);
      r.steps.forEach((s) => { const tr = el("tr");
        cell(tr, String(s.n)); cell(tr, s.verifier_id); cell(tr, fmtUsd(s.threshold)); cell(tr, verdictText(s.response, s.answer)); cell(tr, fmtCount(s.feasible_after.size)); tb.appendChild(tr); });
    } catch (e) { if (e.status === 404) dropSession(e.message); else $("attack-error").textContent = e.message; }
  }));
  $("story-run").addEventListener("click", () => guarded(loadStory));
  $("chain-refresh").addEventListener("click", () => loadChain());
  $("token-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    return guarded(async () => {
      $("owner-error").textContent = "";
      const tok = $("op-token").value.trim();
      if (!tok) { $("owner-error").textContent = "Paste the operator token printed on the server console."; return; }
      ownerToken = tok;
      try { await refreshOwner(); }
      catch (e) { ownerToken = null; $("owner-error").textContent = e.status === 403 ? "That token was not accepted." : e.message; }
    });
  });

  syncControls();
  guarded(loadStory);
  detectMode();
}
if (typeof module !== "undefined") module.exports = { fmtUsd, fmtCount, shareOf, barGeometry, verdictText, describeVerdict, parseIntegerField, shortDigest };
