// Runs the REAL web/app.js against the REAL server in LIVE NEAR mode, whose anchor is a Python MODEL of the contract
// (tests/test_near_app.py). NOT a browser, NOT the real NEAR network: it checks live-mode wiring and state handling only.
const fs = require("fs"), path = require("path");
const base = process.argv[2], goodToken = process.argv[3];
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
  require("../web/app.js");
  await until(() => !$("live-banner").hidden);
  await until(() => $("chain-version").textContent !== "");      // fake DOM starts empty; set once the chain head loaded
  out.live = { title: document.title, banner: $("live-banner").textContent, noticeHidden: $("notice").hidden,
    createHidden: $("create-form").hidden, tokenFormHidden: $("token-form").hidden, chainShown: !$("chain-panel").hidden,
    attackHidden: $("attack").hidden, askDisabled: $("ask").disabled, hint: $("verifier-hint").textContent,
    ownerViewHidden: $("owner-view").hidden };
  out.chain0 = { contract: $("chain-contract").textContent, signer: $("chain-signer").textContent, version: $("chain-version").textContent,
    digestLen: $("chain-digest").textContent.length, status: $("chain-status").textContent,
    links: $("chain-links").children.map((a) => a.href), verify: $("chain-verify").textContent.slice(0, 40) };

  async function ask(t) {
    $("threshold").value = String(t); await $("ask-form").fire("submit");
    return { verdict: $("verdict").textContent, cls: $("verdict").className, version: $("chain-version").textContent,
             log: rows("vlog"), error: $("ask-error").textContent };
  }
  out.ask1 = await ask(499999);          // confirmed on chain: answer shown
  out.ask2 = await ask(249999);          // write lost: RETRY, no answer, chain version unchanged
  out.ask3 = await ask(249999);          // same threshold again: confirmed
  out.noToken = { ownerViewHidden: $("owner-view").hidden, error: $("owner-error").textContent };

  $("op-token").value = "wrong"; await $("token-form").fire("submit");
  out.badToken = { ownerViewHidden: $("owner-view").hidden, error: $("owner-error").textContent };
  $("op-token").value = goodToken; await $("token-form").fire("submit");
  out.goodToken = { ownerViewHidden: $("owner-view").hidden, sid: $("sid").textContent, ver: $("ver").textContent,
                    commit: $("r-commit").textContent, consistent: $("r-consistent").textContent };
  console.log(JSON.stringify(out));
  process.exit(0);
})().catch((e) => { console.error(String(e && e.stack || e)); process.exit(1); });
