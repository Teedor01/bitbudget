// Runs the REAL web/app.js against the REAL local server using a minimal fake DOM.
// NOT a browser: it checks handler wiring and state handling only. No layout, CSS, focus rendering or CSP behaviour.
const fs = require("fs"), path = require("path");
const base = process.argv[2];
const html = fs.readFileSync(path.join(__dirname, "..", "web", "index.html"), "utf8");

class El {
  constructor(tag, id) { this.tagName = tag.toUpperCase(); this.id = id || ""; this.children = []; this.parentNode = null; this._text = "";
    this.hidden = false; this.disabled = false; this.value = ""; this.className = ""; this.style = {}; this.dataset = {}; this.attrs = {}; this.listeners = {}; }
  get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join(" ") : this._text; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); return c; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  setAttribute(k, v) { this.attrs[k] = String(v); } removeAttribute(k) { delete this.attrs[k]; }
  focus() { document.activeElement = this; }
  querySelector(sel) { const want = sel.toUpperCase(), q = this.children.slice(); while (q.length) { const n = q.shift(); if (n.tagName === want) return n; q.push(...n.children); } return null; }
  closest(sel) { const want = sel.toUpperCase(); let n = this; while (n) { if (n.tagName === want) return n; n = n.parentNode; } return null; }
  async fire(type, extra) {
    const ev = Object.assign({ type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } }, extra || {});
    await Promise.all((this.listeners[type] || []).map((f) => f(ev))); return ev;
  }
}
const registry = {};
for (const m of html.matchAll(/<(\w+)([^>]*?)\bid="([^"]+)"([^>]*)>/g)) {
  const [, tag, pre, id, post] = m, attrs = pre + " " + post, e = new El(tag, id);
  e.hidden = /\bhidden\b/.test(attrs); e.disabled = /\bdisabled\b/.test(attrs);
  const v = attrs.match(/\bvalue="([^"]*)"/); if (v) e.value = v[1];
  if (tag === "table") e.appendChild(new El("tbody", ""));
  registry[id] = e;
}
registry.verifier.value = "V1"; registry.strategy.value = "squeeze";
const quickButtons = [];
for (const m of html.matchAll(/<button type="button" data-t="(\d+)">/g)) { const b = new El("button", ""); b.dataset.t = m[1]; b.parentNode = registry.quick; quickButtons.push(b); }
global.document = { getElementById: (id) => { if (!registry[id]) throw new Error("missing element #" + id); return registry[id]; },
  createElement: (t) => new El(t, ""), activeElement: null };
const realFetch = global.fetch; let nextFetch = null;
global.fetch = (p, o) => { if (nextFetch) { const f = nextFetch; nextFetch = null; return f(); } return realFetch(new URL(p, base), o); };

const $ = (id) => registry[id];
const until = async (pred, ms) => { const t0 = Date.now(); while (!pred()) { if (Date.now() - t0 > (ms || 8000)) throw new Error("timeout"); await new Promise((r) => setTimeout(r, 10)); } };
const rows = (id) => $(id).querySelector("tbody").children.map((tr) => tr.children.map((td) => td.textContent));
const out = {};

(async () => {
  const before = { createDisabledWhileLoading: null };
  require("../web/app.js");
  before.createDisabledWhileLoading = $("create").disabled;             // story request is in flight
  await until(() => !$("story-gated").hidden);
  out.initial = { loadingDisabledCreate: before.createDisabledWhileLoading, askDisabled: $("ask").disabled, attackDisabled: $("attack").disabled,
    ownerViewHidden: $("owner-view").hidden, auditorEmptyHidden: $("auditor-empty").hidden, resultText: $("verdict").textContent,
    hint: $("verifier-hint").textContent, createDisabledAfterStory: $("create").disabled };
  out.story = { status: $("story-status").textContent, openHeadline: $("open-headline").textContent, openSeq: $("open-seq").textContent,
    steps: $("gated-steps").children.map((li) => li.textContent), summary: $("gated-summary").textContent,
    floorLeft: $("gated-steps").children[1].children[2].children[1].style.left, firstBarWidth: $("gated-steps").children[0].children[2].children[0].style.width };

  // create: invalid, then valid via the form's submit event (what Enter does)
  $("income").value = "-5"; let ev = await $("create-form").fire("submit");
  out.createInvalid = { prevented: ev.defaultPrevented, error: $("owner-error").textContent, ownerViewHidden: $("owner-view").hidden };
  $("income").value = "120000"; ev = await $("create-form").fire("submit");
  out.created = { prevented: ev.defaultPrevented, secret: $("secret").textContent, fsize: $("fsize").textContent, askDisabled: $("ask").disabled,
    attackDisabled: $("attack").disabled, hintHidden: $("verifier-hint").hidden, focused: document.activeElement && document.activeElement.id };

  const snapshotVerifier = () => ({ verdict: $("verdict").textContent, verdictClass: $("verdict").className, error: $("ask-error").textContent,
    hint: $("verifier-hint").textContent, log: rows("vlog"), threshold: $("threshold").value, verifierValue: $("verifier").value });
  $("verifier").value = "V2"; $("threshold").value = "9998"; await $("ask-form").fire("submit");
  out.refused = { v: snapshotVerifier(), decision: $("r-decision").textContent, range: $("r-range").textContent, fsize: $("fsize").textContent, commit: $("r-commit").textContent };
  $("verifier").value = "V1"; $("threshold").value = "500000"; await $("ask-form").fire("submit");
  out.answered = { v: snapshotVerifier(), decision: $("r-decision").textContent, range: $("r-range").textContent, fsize: $("fsize").textContent, consistent: $("r-consistent").textContent, auditLog: rows("log") };

  // double submit while a request is in flight: exactly one new row
  const rowsBefore = rows("vlog").length; $("threshold").value = "250000";
  await Promise.all([$("ask-form").fire("submit"), $("ask-form").fire("submit")]);
  out.doubleSubmit = { added: rows("vlog").length - rowsBefore };

  $("threshold").value = "abc"; const rb = rows("vlog").length; await $("ask-form").fire("submit");
  out.badThreshold = { error: $("ask-error").textContent, added: rows("vlog").length - rb };
  await $("quick").fire("click", { target: quickButtons.find((b) => b.dataset.t === "9999") });
  out.quick = { threshold: $("threshold").value };

  await $("attack").fire("click");
  out.attack = { resultHidden: $("attack-result").hidden, base: $("attack-base").textContent, gated: $("attack-gated").textContent, steps: rows("steps").length, error: $("attack-error").textContent,
    ownerFsizeAfter: $("fsize").textContent };

  // client-side error states: network failure, then the session disappearing (server restart)
  nextFetch = () => Promise.reject(new TypeError("fetch failed")); $("threshold").value = "4000"; await $("ask-form").fire("submit");
  out.networkDown = { error: $("ask-error").textContent, askDisabledAfter: $("ask").disabled };
  nextFetch = () => Promise.resolve(new Response(JSON.stringify({ error: "unknown session" }), { status: 404, headers: { "Content-Type": "application/json" } }));
  await $("ask-form").fire("submit");
  out.sessionGone = { ownerViewHidden: $("owner-view").hidden, auditorEmptyHidden: $("auditor-empty").hidden, askDisabled: $("ask").disabled, attackDisabled: $("attack").disabled,
    hint: $("verifier-hint").textContent, hintHidden: $("verifier-hint").hidden, ownerError: $("owner-error").textContent, vlogRows: rows("vlog").length };
  // story failure state
  nextFetch = () => Promise.reject(new TypeError("fetch failed")); await $("story-run").fire("click");
  out.storyError = { status: $("story-status").textContent };
  await $("story-run").fire("click");
  out.storyRecovered = { status: $("story-status").textContent, steps: $("gated-steps").children.length };
  console.log(JSON.stringify(out));
})().catch((e) => { console.error("E2E FAILED:", e.stack); process.exit(1); });
