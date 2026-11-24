"use strict";
// The broker's admin console. It calls the admin API beside it (../usage, ../quotas, ../policy, ...)
// and builds every element with textContent: a principal, project or model name is never parsed as
// markup. It keeps nothing in browser storage; the open tab is the URL fragment.

const $ = id => document.getElementById(id);
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const k in props || {}) {
    const v = props[k];
    if (v == null || v === false) continue;
    if (k === "text") e.textContent = v;
    else if (k === "class") e.className = v;
    else if (k === "on") for (const ev in v) e.addEventListener(ev, v[ev]);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids) if (c != null) e.append(c);
  return e;
}
const svgEl = (tag, attrs) => { const e = document.createElementNS("http://www.w3.org/2000/svg", tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
const ymd = d => d.toISOString().slice(0, 10);
const daysAgo = n => ymd(new Date(Date.now() - n * 864e5));
const monthStart = () => ymd(new Date()).slice(0, 8) + "01";
const num = n => n >= 1e9 ? (n / 1e9).toFixed(2) + "B" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n);
const usd = n => n == null ? "-" : "$" + (n > 0 && n < 1 ? n.toFixed(4) : n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
// int formats a whole number with thousands separators, the same for every admin's locale.
const int = n => Number(n).toLocaleString("en-US");
const when = s => s ? s.replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC") : "-";
const isPipeline = p => p.startsWith("ci:");
const ME = (document.querySelector('meta[name="badger-user"]') || {}).content || "";
const same = (a, b) => !!a && !!b && a.toLowerCase() === b.toLowerCase();

// api calls the admin API. It never throws: a failure comes back as ok false with a message.
async function api(path, opts) {
  opts = opts || {};
  const headers = { accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.version !== undefined) headers["If-Match"] = '"' + opts.version + '"';
  let r;
  try {
    r = await fetch("../" + path, { method: opts.method || "GET", credentials: "same-origin", headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  } catch (e) {
    return { ok: false, status: 0, message: "The broker did not answer." };
  }
  let body = null;
  try { body = await r.json(); } catch (e) { /* not JSON: reported below */ }
  const err = body && body.error;
  let message = err ? err.message + (err.details ? ": " + err.details.join("; ") : "") : body ? "" : "The broker sent something that is not JSON (HTTP " + r.status + ").";
  if (!r.ok && !message) message = "HTTP " + r.status;
  return { ok: r.ok, status: r.status, body, message };
}

function status(text, bad) { const s = $("status"); s.textContent = text || ""; s.className = "status" + (bad ? " err" : ""); }

function frac(used, limit) { return limit == null ? null : limit === 0 ? 1 : used / limit; }
function level(f) { return f == null ? "" : f >= 1 ? "over" : f >= 0.8 ? "near" : "ok"; }
function meter(f) { const i = el("i", { class: level(f) }); i.style.width = Math.min(100, Math.max(0, (f || 0) * 100)) + "%"; return el("div", { class: "meter", role: "img", "aria-label": f == null ? "no limit" : Math.round(f * 100) + "% used" }, i); }
function pill(f) { const l = level(f); return l ? el("span", { class: "pill " + l, text: { ok: "OK", near: "Near limit", over: "At limit" }[l] }) : el("span", { class: "s", text: "No limit" }); }
function kindTag(p) { return el("span", { class: "tag " + (isPipeline(p) ? "pipeline" : "person"), text: isPipeline(p) ? "Workload" : "Person" }); }
function emptyRow(cols, text) { return el("tr", {}, el("td", { class: "msg", colspan: cols, text })); }
function cellN(text) { return el("td", { class: "n", text }); }

// ---- shared state, loaded once and refreshed after each write ----
const S = { quotas: null, config: null, policy: null, owners: null, proposals: [] };

async function loadQuotas() { const r = await api("quotas"); if (r.ok) S.quotas = r.body; return r; }
async function loadWorkloadData() {
  const [c, p, o, pr] = await Promise.all([api("config"), api("policy"), api("owners"), api("proposals")]);
  for (const r of [c, p, o]) if (!r.ok) return r;
  S.config = c.body; S.policy = p.body; S.owners = o.body; S.proposals = pr.ok ? pr.body.proposals || [] : [];
  const humans = S.owners.humans || [], workloads = (S.policy.entries || []).map(e => e.principal);
  $("qd-people").replaceChildren(...humans.map(h => el("option", { value: h })));
  // Agent limits are for people: a workload calls the models directly, with no managed agent.
  $("ld-people").replaceChildren(...humans.map(h => el("option", { value: h })));
  $("lk-list").replaceChildren(...[...humans, ...workloads].map(h => el("option", { value: h })));
  const ms = $("us-model"); const cur = ms.value;
  ms.replaceChildren(el("option", { value: "", text: "All models" }), ...(S.config.models || []).map(m => el("option", { value: m, text: m })));
  ms.value = cur;
  return c;
}
// ownerOf is the person who answers for a pipeline principal, from the owners view.
function ownerOf(p) { const e = ((S.owners && S.owners.entries) || []).find(x => x.principal === p); return e ? e.owner : null; }
function isMine(p) { return p !== "default" && (same(p, ME) || same(ownerOf(p), ME)); }

// effective is a principal's limits: their own value for each field, else the default's.
function effective(q, p) {
  const own = (q.people || {})[p] || {}, d = q.defaults || {};
  const m = (q.principals || {})[p];
  const out = { monthly_usd: m != null ? m : q.default_usd };
  for (const k of ["daily_usd", "call_usd", "steps", "context", "output", "timeout_seconds"]) out[k] = own[k] != null ? own[k] : d[k];
  return out;
}
// resolveLimits is what applies to principal p, field by field, and where each value comes from:
// "own", "default", "built-in" (the managed agent's compiled value) or "none". A workload has no
// managed agent, so it gets no agent fields; its output is capped only by a limit someone set.
const MONEY = [["monthly_usd", "Monthly spend"], ["daily_usd", "Daily spend"], ["call_usd", "Spend per model call"]];
const AGENT = [["steps", "Max agent steps per request"], ["context", "Context window"], ["timeout_seconds", "Timeout per model call"]];
function resolveLimits(q, p) {
  const own = (q.people || {})[p] || {}, d = q.defaults || {}, b = q.built_in || {}, pipe = isPipeline(p);
  const pick = (mine, def, builtIn) => mine != null ? [mine, "own"] : def != null ? [def, "default"] : builtIn != null ? [builtIn, "built-in"] : [null, "none"];
  const out = { monthly_usd: pick((q.principals || {})[p], q.default_usd) };
  for (const k of ["daily_usd", "call_usd"]) out[k] = pick(own[k], d[k]);
  out.output = pick(own.output, d.output, pipe ? null : b.output);
  if (!pipe) for (const [k] of AGENT) out[k] = pick(own[k], d[k], b[k]);
  return out;
}
// showValue is one limit in words, with its unit.
function showValue(k, v) {
  if (v == null) return "No limit";
  if (k.endsWith("_usd")) return usd(v);
  if (k === "timeout_seconds") return int(v) + " s";
  if (k === "steps") return int(v);
  return int(v) + " tokens";
}
const SOURCE = { own: "own", default: "from default", "built-in": "built-in", none: "not set" };
function sourceTag(src) { return el("span", { class: "tag src " + src.replace("-", ""), text: SOURCE[src] }); }

// quotaBody is the PUT body for the quotas document as it stands in q.
function quotaBody(q, comment) { return { default_usd: q.default_usd == null ? null : q.default_usd, principals: q.principals || {}, defaults: q.defaults || {}, people: q.people || {}, comment }; }
function cloneQ(q) { return JSON.parse(JSON.stringify({ default_usd: q.default_usd, principals: q.principals || {}, defaults: q.defaults || {}, people: q.people || {} })); }
// setLimit sets one field of one target ("default" or a principal) in a cloned document; null removes it.
function setLimit(q, target, field, value) {
  if (target === "default") {
    if (field === "monthly_usd") q.default_usd = value;
    else if (value == null) delete q.defaults[field]; else q.defaults[field] = value;
    return;
  }
  if (field === "monthly_usd") { if (value == null) delete q.principals[target]; else q.principals[target] = value; return; }
  const row = Object.assign({}, q.people[target]);
  if (value == null) delete row[field]; else row[field] = value;
  if (Object.keys(row).length) q.people[target] = row; else delete q.people[target];
}
async function saveQuotas(q, comment) {
  const r = await api("quotas", { method: "PUT", version: S.quotas.version, body: quotaBody(q, comment) });
  if (r.status === 412) { await loadQuotas(); return { ok: false, message: "Someone else changed the limits while you edited. They are reloaded: check and save again." }; }
  if (r.ok) await loadQuotas();
  return r;
}

// ---- tabs ----
const TABS = ["overview", "usage", "limits", "workloads"];
// The Quotas and Agent limits tabs became one Limits tab: old links to #quotas open it.
const ALIAS = { quotas: "limits" };
const loaded = {};
function show(name, focus) {
  name = ALIAS[name] || name;
  if (!TABS.includes(name)) name = "overview";
  for (const t of TABS) {
    const on = t === name, tab = $("tab-" + t);
    tab.setAttribute("aria-selected", on ? "true" : "false");
    tab.tabIndex = on ? 0 : -1;
    $("panel-" + t).hidden = !on;
  }
  if (focus) $("tab-" + name).focus();
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
  status("");
  if (!loaded[name]) { loaded[name] = true; RENDER[name](); }
}
function initTabs() {
  for (const t of TABS) {
    const tab = $("tab-" + t);
    tab.addEventListener("click", () => show(t));
    tab.addEventListener("keydown", e => {
      const i = TABS.indexOf(t);
      const to = { ArrowRight: (i + 1) % TABS.length, ArrowLeft: (i + TABS.length - 1) % TABS.length, Home: 0, End: TABS.length - 1 }[e.key];
      if (to !== undefined) { e.preventDefault(); show(TABS[to], true); }
    });
  }
  addEventListener("hashchange", () => show(location.hash.slice(1)));
}

// ---- Overview ----
async function renderOverview() {
  const today = ymd(new Date());
  const [q, month, week, hist] = await Promise.all([loadQuotas(), api("usage/principals?from=" + monthStart() + "&to=" + today),
    api("usage/principals?from=" + daysAgo(6) + "&to=" + today), api("usage?from=" + daysAgo(29) + "&to=" + today)]);
  if (!loaded.owners) { await loadWorkloadData(); loaded.owners = true; }
  for (const r of [q, month, week, hist]) if (!r.ok) return status(r.message, true);
  const Q = S.quotas, rows = month.body.rows;
  const spend = rows.reduce((a, r) => a + (r.cost_usd || 0), 0);
  const active = new Set(week.body.rows.map(r => r.principal));
  const people = [...active].filter(p => !isPipeline(p)).length;
  const alerts = quotaAlerts(Q);
  uncapped(Q);
  const tile = (k, v, s) => el("div", { class: "card" }, el("div", { class: "k", text: k }), el("div", { class: "v", text: v }), el("div", { class: "s", text: s }));
  $("ov-tiles").replaceChildren(
    tile("Spend this month", usd(spend), Q.default_usd != null ? "default limit " + usd(Q.default_usd) + " a month for each person and workload" : "not capped: no default monthly limit"),
    tile("Active people", String(people), "used a model in the last 7 days"),
    tile("Active workloads", String(active.size - people), "pipelines that called a model in the last 7 days"),
    tile("Limit alerts", String(alerts.length), "at or above 80% of a monthly or daily limit"));
  // Top users and models this month.
  const by = (key) => { const m = {}; for (const r of rows) { const a = m[r[key]] || (m[r[key]] = { name: r[key], cost: 0, req: 0 }); a.cost += r.cost_usd || 0; a.req += r.requests; } return Object.values(m).sort((a, b) => b.cost - a.cost || b.req - a.req); };
  const top = by("principal").slice(0, 5);
  $("ov-top").replaceChildren(el("tr", {}, el("th", { text: "Who" }), el("th", { class: "n", text: "Requests" }), el("th", { class: "n", text: "Spend" }), el("th", { text: "Share of spend" })),
    ...(top.length ? top.map(a => el("tr", {}, el("td", {}, a.name, kindTag(a.name)), cellN(a.req.toLocaleString()), cellN(usd(a.cost)), el("td", {}, meter(spend ? a.cost / spend : 0)))) : [emptyRow(4, "No use this month.")]));
  const models = by("model");
  $("ov-models").replaceChildren(...(models.length ? models.map(a => el("tr", {}, el("td", { text: a.name }), cellN(usd(a.cost)))) : [emptyRow(2, "No use this month.")]));
  $("ov-alerts").replaceChildren(...(alerts.length ? alerts.slice(0, 8).map(a => el("li", {},
    el("strong", { text: a.who === "default" ? "Everyone" : a.who }), " has used " + Math.round(a.f * 100) + "% of the " + a.period + " limit of " + usd(a.limit) + ". ", pill(a.f), el("br"),
    el("button", { text: "Open limit", on: { click: () => { show("limits"); openQuota(a.who, a.field); } } }))) : [el("li", { class: "s", text: "Nothing near a limit." })]));
  // Daily spend, last 30 days.
  const days = hist.body.days || {}, list = [];
  for (let i = 29; i >= 0; i--) list.push(daysAgo(i));
  const val = list.map(d => { let s = 0; for (const p in days[d] || {}) for (const m in days[d][p]) s += days[d][p][m].cost_usd || 0; return s; });
  chart($("ov-chart"), list, val);
}
function quotaAlerts(Q) {
  const out = [], used = Q.used_usd || {}, today = Q.today_usd || {};
  const names = new Set([...Object.keys(Q.principals || {}), ...Object.keys(Q.people || {}), ...Object.keys(used)]);
  for (const p of names) {
    const e = effective(Q, p);
    for (const [field, period, spent] of [["monthly_usd", "monthly", used[p] || 0], ["daily_usd", "daily", today[p] || 0]]) {
      const f = frac(spent, e[field]);
      if (f != null && f >= 0.8) out.push({ who: p, field, period, limit: e[field], f });
    }
  }
  return out.sort((a, b) => b.f - a.f);
}
function chart(box, list, val) {
  const max = Math.max(0, ...val);
  if (!max) { box.replaceChildren(el("p", { class: "note", text: "No priced use in the last 30 days." })); return; }
  const W = 1000, H = 200, L = 56, B = 24;
  const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + (H + B), role: "img", "aria-label": "Daily spend for the last 30 days, highest " + usd(max) });
  for (let i = 0; i <= 4; i++) {
    const y = H - (H - 10) * i / 4;
    svg.append(svgEl("line", { x1: L, x2: W, y1: y, y2: y, class: "grid" }));
    const t = svgEl("text", { x: L - 6, y: y + 4, class: "ax", "text-anchor": "end" }); t.textContent = usd(max * i / 4); svg.append(t);
  }
  const bw = (W - L) / list.length;
  list.forEach((d, i) => {
    const h = val[i] / max * (H - 10), x = L + i * bw;
    const r = svgEl("rect", { x: x + 2, y: H - h, width: Math.max(bw - 4, 1), height: Math.max(h, 0), class: "barfill" });
    const tt = svgEl("title", {}); tt.textContent = d + ": " + usd(val[i]); r.append(tt); svg.append(r);
    if (i % 5 === 4 || i === 0) { const t = svgEl("text", { x: x + bw / 2, y: H + 17, class: "ax", "text-anchor": "middle" }); t.textContent = d.slice(5); svg.append(t); }
  });
  box.replaceChildren(svg);
}

// ---- Usage ----
let usageRows = [], sortKey = "cost_usd", sortDir = -1;
function usageRange() {
  const v = $("us-range").value, to = ymd(new Date());
  $("us-dates").hidden = v !== "custom";
  if (v === "custom") return [$("us-from").value || daysAgo(6), $("us-to").value || to];
  if (v === "month") return [monthStart(), to];
  return [daysAgo(Number(v) - 1), to];
}
function usageQuery() {
  const [from, to] = usageRange();
  let q = "from=" + encodeURIComponent(from) + "&to=" + encodeURIComponent(to);
  if ($("us-kind").value) q += "&kind=" + encodeURIComponent($("us-kind").value);
  if ($("us-model").value) q += "&model=" + encodeURIComponent($("us-model").value);
  return q;
}
async function renderUsage() {
  if (!loaded.owners) { await loadWorkloadData(); loaded.owners = true; }
  $("us-table").replaceChildren(emptyRow(1, "Loading…"));
  const r = await api("usage/principals?" + usageQuery());
  if (!r.ok) { $("us-table").replaceChildren(emptyRow(1, r.message)); return status(r.message, true); }
  usageRows = r.body.rows;
  $("us-foot").textContent = "Counting began " + when(r.body.since) + "; earlier days have no record. Cost is what each call was charged at its model's configured price when it ran; a model with no price shows a dash, not zero. One view covers at most 92 days.";
  usageTable();
}
function shownUsage() {
  const s = $("us-search").value.trim().toLowerCase();
  const rows = s ? usageRows.filter(r => [r.principal, r.owner, r.triggered_by, r.model].some(x => x && x.toLowerCase().includes(s))) : usageRows;
  return [...rows].sort((a, b) => { const x = a[sortKey], y = b[sortKey]; return (typeof x === "string" ? (x || "").localeCompare(y || "") : (x == null ? -1 : x) - (y == null ? -1 : y)) * sortDir; });
}
function usageTable() {
  const rows = shownUsage();
  const cols = [["principal", "Who"], ["model", "Model"], ["triggered_by", "Started by"], ["requests", "Requests", 1], ["prompt_tokens", "Input tokens", 1], ["completion_tokens", "Output tokens", 1], ["cost_usd", "Cost", 1], ["last_used", "Last active"]];
  const head = el("tr", {}, ...cols.map(([k, label, n]) => el("th", { class: n ? "n" : null, "aria-sort": sortKey === k ? (sortDir < 0 ? "descending" : "ascending") : null },
    el("button", { text: label + (sortKey === k ? (sortDir < 0 ? " ↓" : " ↑") : ""), on: { click: () => { sortDir = sortKey === k ? -sortDir : -1; sortKey = k; usageTable(); } } }))));
  const t = { requests: 0, prompt_tokens: 0, completion_tokens: 0, cost: 0, priced: false };
  const body = rows.map(r => {
    t.requests += r.requests; t.prompt_tokens += r.prompt_tokens; t.completion_tokens += r.completion_tokens;
    if (r.cost_usd != null) { t.cost += r.cost_usd; t.priced = true; }
    const who = el("td", {}, r.principal, kindTag(r.principal));
    if (isPipeline(r.principal)) who.append(el("span", { class: "sub", text: r.owner ? "owner " + r.owner : "no owner recorded" }));
    return el("tr", {}, who, el("td", { text: r.model }), el("td", { text: r.triggered_by || (isPipeline(r.principal) ? "-" : "") }),
      cellN(r.requests.toLocaleString()), cellN(num(r.prompt_tokens)), cellN(num(r.completion_tokens)), cellN(usd(r.cost_usd)), el("td", { text: when(r.last_used) }));
  });
  const total = el("tr", { class: "total" }, el("td", { text: "Total" }), el("td"), el("td"), cellN(t.requests.toLocaleString()), cellN(num(t.prompt_tokens)), cellN(num(t.completion_tokens)), cellN(t.priced ? usd(t.cost) : "-"), el("td"));
  $("us-table").replaceChildren(el("caption", { class: "note", text: rows.length + " rows" }), head, ...(rows.length ? body : [emptyRow(cols.length, "No use in this range.")]), total);
}
const csvCell = s => { s = s == null ? "" : String(s); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function download(name, lines) {
  const a = el("a", { download: name });
  a.href = URL.createObjectURL(new Blob([lines.map(l => l.map(csvCell).join(",")).join("\n") + "\n"], { type: "text/csv" }));
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function usageCSV() {
  const [from, to] = usageRange();
  download("model-usage-" + from + "-to-" + to + ".csv", [["principal", "kind", "model", "owner", "triggered_by", "requests", "prompt_tokens", "cached_prompt_tokens", "completion_tokens", "cost_usd", "last_used"],
    ...shownUsage().map(r => [r.principal, r.kind, r.model, r.owner, r.triggered_by, r.requests, r.prompt_tokens, r.cached_prompt_tokens, r.completion_tokens, r.cost_usd, r.last_used])]);
}
async function dailyCSV() {
  const [from, to] = usageRange();
  const r = await api("usage?" + usageQuery());
  if (!r.ok) return status(r.message, true);
  const lines = [["day", "principal", "model", "requests", "prompt_tokens", "cached_prompt_tokens", "completion_tokens", "cost_usd"]];
  for (const day of Object.keys(r.body.days).sort()) for (const p of Object.keys(r.body.days[day]).sort()) for (const m of Object.keys(r.body.days[day][p]).sort()) {
    const c = r.body.days[day][p][m];
    lines.push([day, p, m, c.requests, c.prompt_tokens, c.cached_prompt_tokens || 0, c.completion_tokens, c.cost_usd]);
  }
  download("model-usage-daily-" + from + "-to-" + to + ".csv", lines);
}

// ---- Limits: spend and output (the broker), agent behavior (the managed agent) ----
// uncapped shows the warning on Overview and Limits when no default monthly limit is set.
function uncapped(Q) { for (const id of ["ov-uncapped", "lt-uncapped"]) $(id).hidden = Q.default_usd != null; }
function setDefault() { show("limits"); openQuota("default", "monthly_usd"); }
async function renderLimits() {
  const r = await loadQuotas();
  if (!loaded.owners) { await loadWorkloadData(); loaded.owners = true; }
  if (!r.ok) return status(r.message, true);
  uncapped(S.quotas);
  spendTable(); agentTable();
  if ($("lk-who").value.trim()) lookup();
}
function spendTable() {
  const Q = S.quotas, used = Q.used_usd || {}, today = Q.today_usd || {}, d = Q.defaults || {};
  const own = p => { const pp = (Q.people || {})[p] || {}; return (Q.principals || {})[p] != null || pp.daily_usd != null || pp.call_usd != null || pp.output != null; };
  const names = [...new Set([...Object.keys(Q.principals || {}), ...Object.keys(Q.people || {})])].filter(own).sort();
  const fields = [["monthly_usd", "Monthly"], ["daily_usd", "Daily"], ["call_usd", "Per model call"], ["output", "Output per call"]];
  const head = el("tr", {}, el("th", { text: "Applies to" }), ...fields.map(([, h]) => el("th", { class: "n", text: h })),
    ...["Used this month", "Today", "Status", ""].map(h => el("th", { text: h })));
  // A value, marked when it comes from the default; an unset monthly default is spending without bound.
  const cell = (k, v, src) => el("td", { class: "n" },
    v != null ? showValue(k, v) : k === "monthly_usd" && src === "default-row" ? el("span", { class: "tag bad", text: "not capped" }) : el("span", { class: "s", text: "no limit" }),
    v != null && src === "default" ? el("span", { class: "sub", text: "from default" }) : null);
  const defaultRow = () => {
    const humans = (S.owners && S.owners.humans) || [], wls = ((S.policy && S.policy.entries) || []).map(e => e.principal);
    const without = list => list.filter(p => (Q.principals || {})[p] == null).length;
    const n = without(humans), m = without(wls);
    return el("tr", { "data-who": "default" }, el("td", {}, el("strong", { text: "Everyone (default)" })),
      cell("monthly_usd", Q.default_usd, "default-row"), cell("daily_usd", d.daily_usd), cell("call_usd", d.call_usd), cell("output", d.output),
      el("td", { colspan: 3, class: "s", text: "Applies to each person and workload individually. Covers " + n + (n === 1 ? " person" : " people") + " and " + m + (m === 1 ? " workload" : " workloads") + " without a monthly limit of their own." }),
      el("td", {}, el("button", { text: "Edit", "aria-label": "Edit the default limits for everyone", on: { click: () => openQuota("default", "monthly_usd") } })));
  };
  const row = p => {
    const e = resolveLimits(Q, p);
    const m = frac(used[p] || 0, e.monthly_usd[0]), dd = frac(today[p] || 0, e.daily_usd[0]);
    const worst = m == null ? dd : dd == null ? m : Math.max(m, dd);
    const who = el("td", {}, el("strong", { text: p }), kindTag(p));
    if (isPipeline(p)) who.append(el("span", { class: "sub", text: ownerOf(p) ? "owner " + ownerOf(p) : "no owner" }));
    const out = e.output[1] === "built-in" ? [null, "none"] : e.output; // the broker caps output only when a limit is set
    return el("tr", { "data-who": p }, who, ...fields.map(([k]) => cell(k, (k === "output" ? out : e[k])[0], (k === "output" ? out : e[k])[1])),
      el("td", {}, meter(m), el("span", { class: "sub", text: usd(used[p] || 0) + (m != null ? " (" + Math.round(m * 100) + "%)" : "") })),
      el("td", { text: usd(today[p] || 0) }), el("td", {}, pill(worst)),
      el("td", {}, el("button", { text: "Edit", "aria-label": "Edit limits for " + p, on: { click: () => openQuota(p, "monthly_usd") } })));
  };
  $("qt-table").replaceChildren(head, defaultRow(), ...names.map(row));
  if (!names.length) $("qt-table").append(emptyRow(9, "No person or workload has a spend or output limit of their own: each gets the default."));
}
// lookup fills the effective-limits table for the person or workload typed in.
function lookup() {
  const p = $("lk-who").value.trim();
  if (!p) { $("lk-table").replaceChildren(); return; }
  const e = resolveLimits(S.quotas, p);
  const rows = [...MONEY, ["output", "Output per model call"], ...(isPipeline(p) ? [] : AGENT)].map(([k, label]) =>
    el("tr", { "data-field": k, "data-source": e[k][1] }, el("th", { scope: "row", text: label }), el("td", { class: "n", text: showValue(k, e[k][0]) }), el("td", {}, sourceTag(e[k][1])),
      el("td", { class: "s", text: k === "output" && e[k][1] === "built-in" ? "the agent asks for at most this; the broker sets no cap" : AGENT.some(([a]) => a === k) ? "applied by the agent at session start" : "enforced by the broker" })));
  $("lk-table").replaceChildren(el("caption", { class: "note", text: (isPipeline(p) ? "Workload " : "") + p + (isPipeline(p) ? ": a workload has no managed agent, so agent limits do not apply." : "") }), ...rows);
}
function workloadOptions(sel, current) {
  const es = ((S.policy && S.policy.entries) || []);
  sel.replaceChildren(...es.map(e => el("option", { value: e.principal, text: e.id + " (" + e.principal + ")" })));
  if (current) sel.value = current;
}
function quotaTarget() {
  const scope = $("qd-scope").value;
  return scope === "default" ? "default" : scope === "workload" ? $("qd-wl").value : $("qd-who").value.trim();
}
function quotaCurrent(target, field) {
  const Q = S.quotas;
  if (target === "default") return field === "monthly_usd" ? Q.default_usd : (Q.defaults || {})[field];
  return field === "monthly_usd" ? (Q.principals || {})[target] : ((Q.people || {})[target] || {})[field];
}
const HOW = {
  monthly_usd: "Resets at 00:00 UTC on the 1st of each month. From 80% the broker adds a warning to each answer; at 100% new requests are refused until it resets.",
  daily_usd: "Resets at 00:00 UTC each day. From 80% the broker adds a warning to each answer; at 100% new requests are refused until it resets.",
  call_usd: "The most one model call may cost: the broker shortens the answer to fit, at the model's output price.",
  output: "The broker caps every model call's answer at this many tokens.",
};
function quotaPreview() {
  const target = quotaTarget(), field = $("qd-period").value, Q = S.quotas;
  const tokens = field === "output", amount = $("qd-amount");
  amount.step = tokens ? "1" : "0.01"; amount.min = tokens ? "1" : "0";
  if (tokens) amount.max = String((Q.technical || {}).max_output || ""); else amount.removeAttribute("max");
  $("qd-how").textContent = HOW[field];
  $("qd-who").hidden = $("qd-scope").value !== "person";
  $("qd-wl").hidden = $("qd-scope").value !== "workload";
  $("qd-self").hidden = !isMine(target);
  const amt = $("qd-amount").value === "" ? null : Number($("qd-amount").value);
  if (!target) { $("qd-preview").textContent = ""; return; }
  if (target === "default") { $("qd-preview").textContent = "Applies to each person and workload individually, unless they have a limit of their own."; return; }
  const spent = field === "daily_usd" ? (Q.today_usd || {})[target] || 0 : (Q.used_usd || {})[target] || 0;
  const span = field === "daily_usd" ? "today" : "this month";
  if (field === "call_usd") { $("qd-preview").textContent = amt == null ? "No per-call limit of their own." : "Each call may cost at most " + usd(amt) + "; longer answers are cut to fit."; return; }
  if (tokens) { $("qd-preview").textContent = amt == null ? "No output limit of their own." : "Each answer may be at most " + int(amt) + " tokens."; return; }
  $("qd-preview").textContent = target + " has used " + usd(spent) + " " + span + "." + (amt == null ? "" : amt > spent ? " This limit leaves " + usd(amt - spent) + "." : " This limit stops new requests now.");
}
function openQuota(target, field) {
  const d = $("qd");
  $("qd-msg").textContent = ""; $("qd-reason").value = "";
  workloadOptions($("qd-wl"), target && isPipeline(target) ? target : null);
  $("qd-scope").value = !target ? "person" : target === "default" ? "default" : isPipeline(target) ? "workload" : "person";
  $("qd-who").value = target && target !== "default" && !isPipeline(target) ? target : "";
  $("qd-period").value = field || "monthly_usd";
  $("qd-title").textContent = target === "default" ? "Set a limit for everyone (default)" : target ? "Set a limit for " + target : "Set a limit";
  prices();
  const fill = () => { const v = quotaCurrent(quotaTarget(), $("qd-period").value); $("qd-amount").value = v == null ? "" : String(v); quotaPreview(); };
  $("qd-scope").onchange = fill; $("qd-who").onchange = fill; $("qd-wl").onchange = fill; $("qd-period").onchange = fill;
  $("qd-who").oninput = quotaPreview; $("qd-amount").oninput = quotaPreview;
  fill();
  d.showModal();
}
// prices lists each model's price on the editor, so an admin can size a budget from it.
function prices() {
  const P = (S.config && S.config.prices) || {}, models = Object.keys(P).sort();
  const per = n => "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 4 });
  $("qd-prices").replaceChildren(...(models.length ? [el("p", { class: "note", text: "Model prices, US dollars per 1 million tokens:" }),
    el("table", {}, el("tr", {}, ...["Model", "Input", "Cached input", "Output"].map(h => el("th", { class: h === "Model" ? null : "n", text: h }))),
      ...models.map(m => el("tr", {}, el("td", { text: m }), cellN(per(P[m].input)), cellN(per(P[m].cached_input)), cellN(per(P[m].output)))))]
    : [el("p", { class: "note", text: "No model has a price configured, so spend is counted as zero and money limits never trigger." })]));
}
async function submitQuota() {
  const target = quotaTarget();
  if (!target) { $("qd-msg").textContent = "Say who the limit is for."; return; }
  const v = $("qd-amount").value;
  if (v !== "" && !(Number(v) >= 0)) { $("qd-msg").textContent = "The amount must be zero or more."; return; }
  if (v !== "" && $("qd-period").value === "output" && !(Number.isInteger(Number(v)) && Number(v) >= 1)) { $("qd-msg").textContent = "Output is a whole number of tokens, at least 1."; return; }
  const q = cloneQ(S.quotas);
  setLimit(q, target, $("qd-period").value, v === "" ? null : Number(v));
  $("qd-msg").textContent = "Saving…";
  const r = await saveQuotas(q, $("qd-reason").value.trim());
  if (!r.ok) { $("qd-msg").textContent = r.message; return; }
  $("qd").close(); status("Saved as version " + S.quotas.version + ".");
  loaded.overview = false; renderLimits();
}

// ---- Workloads ----
const entryPrincipal = e => "ci:" + (e.issuer ? e.issuer + ":" : "") + e.project_path + (e.kind === "named_branch" ? "@" + e.ref : "");
async function renderWorkloads() {
  const [r, q] = await Promise.all([loadWorkloadData(), loadQuotas()]);
  loaded.owners = true;
  if (!r.ok) return status(r.message, true);
  if (!q.ok) return status(q.message, true);
  const es = S.policy.entries || [];
  const head = el("tr", {}, ...["Workload", "Project and branch", "Started by", "Models", "Owner", "Monthly limit", "Expires", ""].map(h => el("th", { text: h })));
  const rows = es.map(e => {
    const owner = ownerOf(e.principal);
    const quota = (S.quotas.principals || {})[e.principal];
    return el("tr", { "data-id": e.id },
      el("td", {}, el("strong", { text: e.id }), e.enabled ? null : el("span", { class: "tag", text: "disabled" }), el("span", { class: "sub", text: e.principal })),
      el("td", {}, e.project_path, el("span", { class: "sub", text: (e.kind === "named_branch" ? "branch " + e.ref + ", even unprotected" : "protected branch " + e.ref) })),
      el("td", {}, (e.sources || []).join(", "), e.trigger_users && e.trigger_users.length ? el("span", { class: "sub", text: "only " + e.trigger_users.join(", ") }) : null),
      el("td", {}, ...(e.models || []).map(m => el("span", { class: "chip", text: m }))),
      el("td", {}, owner || el("span", { class: "tag bad", text: "no owner: refused" })),
      el("td", { text: quota != null ? usd(quota) : S.quotas.default_usd != null ? "default " + usd(S.quotas.default_usd) : "not capped" }),
      el("td", { text: e.expires_at ? e.expires_at.slice(0, 10) : "never" }),
      el("td", {}, el("button", { text: "Edit", "aria-label": "Edit workload " + e.id, on: { click: () => openWorkload(e) } })));
  });
  $("wl-table").replaceChildren(head, ...(rows.length ? rows : [emptyRow(8, "No workloads yet. Add one to let a pipeline call the models.")]));
  const ps = S.proposals;
  $("wl-proposals-card").hidden = !ps.length;
  $("wl-proposals").replaceChildren(el("tr", {}, ...["Proposal", "By", "Comment", ""].map(h => el("th", { text: h }))),
    ...ps.map(p => el("tr", {}, el("td", { text: "#" + p.id + " (from version " + p.base + ")" }), el("td", { text: p.author_name || p.author }), el("td", { text: p.comment || "" }),
      el("td", {}, el("button", { text: "Approve", on: { click: () => decide(p.id, "approve") } }), " ", el("button", { text: "Reject", on: { click: () => decide(p.id, "reject") } })))));
}
async function decide(id, what) {
  const r = await api("proposals/" + id + "/" + what, { method: "POST" });
  status(r.ok ? (what === "approve" ? "Approved; the policy is updated." : "Rejected.") : r.message, !r.ok);
  renderWorkloads();
}
let editing = null;
function checks(box, name, all, on) {
  box.replaceChildren(...all.map(v => el("label", { class: "check" }, el("input", { type: "checkbox", name, value: v, checked: on.includes(v) }), " " + v)));
}
function openWorkload(e) {
  editing = e || null;
  const c = S.config;
  e = e || { id: "", issuer: "", kind: "protected_branch", project_path: "", ref: "main", sources: [], models: [], trigger_users: [], expires_at: null, enabled: true };
  $("wd-title").textContent = editing ? "Edit workload " + e.id : "Add workload";
  $("wd-id").value = e.id; $("wd-id").readOnly = !!editing;
  const issuers = c.issuers || [];
  $("wd-issuer-field").hidden = issuers.length < 2;
  $("wd-issuer").replaceChildren(...issuers.map(i => el("option", { value: i.primary ? "" : i.id, text: i.id + " (" + i.issuer + ")" })));
  $("wd-issuer").value = e.issuer || "";
  $("wd-project").value = e.project_path; $("wd-ref").value = e.ref;
  $("wd-kind-" + (e.kind === "named_branch" ? "named" : "protected")).checked = true;
  $("wd-two").textContent = c.two_person_rule ? "; another admin must approve" : "";
  checks($("wd-sources"), "wd-source", c.sources || [], e.sources || []);
  checks($("wd-models"), "wd-model", c.models || [], e.models || []);
  $("wd-users").value = (e.trigger_users || []).join(", ");
  $("wd-expires").value = e.expires_at ? e.expires_at.slice(0, 10) : "";
  $("wd-enabled").checked = !!e.enabled;
  const owner = editing ? ownerOf(e.principal) : "";
  $("wd-owner").replaceChildren(el("option", { value: "", text: "Choose a person" }), ...(S.owners.humans || []).map(h => el("option", { value: h, text: h })));
  $("wd-owner").value = owner || "";
  const quota = editing ? (S.quotas.principals || {})[e.principal] : undefined;
  $("wd-quota").value = quota == null ? "" : String(quota);
  $("wd-reason").value = ""; $("wd-msg").textContent = "";
  $("wd").showModal();
}
// submitWorkload writes the owner, then the quota, then the policy entry: the policy write is what
// grants access, so it goes last, and a failure before it leaves nothing new reachable.
async function submitWorkload() {
  const msg = t => { $("wd-msg").textContent = t; };
  const picked = name => [...document.querySelectorAll('input[name="' + name + '"]:checked')].map(i => i.value);
  const kind = $("wd-kind-named").checked ? "named_branch" : "protected_branch";
  const exp = $("wd-expires").value;
  const base = editing ? Object.assign({}, editing) : {};
  delete base.principal;
  const entry = Object.assign(base, {
    id: $("wd-id").value.trim(), kind, issuer: $("wd-issuer").value || undefined, project_path: $("wd-project").value.trim(), ref: $("wd-ref").value.trim(),
    sources: picked("wd-source"), models: picked("wd-model"), trigger_users: $("wd-users").value.split(",").map(s => s.trim()).filter(Boolean),
    expires_at: !exp ? null : editing && editing.expires_at && editing.expires_at.slice(0, 10) === exp ? editing.expires_at : exp + "T23:59:59Z", minted_before: base.minted_before || null, enabled: $("wd-enabled").checked,
  });
  if (!entry.issuer) delete entry.issuer;
  if (!$("wd-owner").value) return msg("Choose the person who answers for this workload.");
  if (!entry.sources.length || !entry.models.length) return msg("Choose at least one way it may be started and one model.");
  const comment = $("wd-reason").value.trim();
  const principal = entryPrincipal(entry), oldPrincipal = editing ? editing.principal : null;
  if (!editing && (S.policy.entries || []).some(e => e.id === entry.id)) return msg("A workload named " + entry.id + " already exists.");
  msg("Saving the owner…");
  const owners = Object.assign({}, S.owners.owners, { [entry.id]: $("wd-owner").value });
  let r = await api("owners", { method: "PUT", version: S.owners.version, body: { owners, comment } });
  if (!r.ok) { await loadWorkloadData(); return msg((r.status === 412 ? "Someone else changed the owners; reloaded. " : "Owner not saved: ") + r.message); }
  const q = cloneQ(S.quotas), qv = $("wd-quota").value;
  const before = JSON.stringify(q.principals);
  // A changed principal keeps its old quota here: the workload runs as the old one until the policy
  // write below takes effect, which a failure or a second admin's approval can stop or delay.
  if (qv === "") delete q.principals[principal]; else q.principals[principal] = Number(qv);
  if (JSON.stringify(q.principals) !== before) {
    msg("Saving the limit…");
    r = await saveQuotas(q, comment);
    if (!r.ok) { await loadWorkloadData(); return msg("The owner is saved; the limit is not: " + r.message); }
  }
  msg("Saving the workload…");
  const entries = (S.policy.entries || []).map(e => { const x = Object.assign({}, e); delete x.principal; return x; });
  const i = entries.findIndex(e => e.id === entry.id);
  if (i >= 0) entries[i] = entry; else entries.push(entry);
  r = await api("policy", { method: "PUT", version: S.policy.version, body: { entries, comment } });
  if (r.status === 412) { await loadWorkloadData(); return msg("Someone else changed the workloads; reloaded. The owner and limit are saved; open the workload again and save."); }
  if (!r.ok) return msg("The owner and limit are saved; the workload is not: " + r.message);
  $("wd").close();
  let note = "";
  // Only once the new principal is in force does the old one's quota go.
  if (r.status !== 202 && oldPrincipal && oldPrincipal !== principal && oldPrincipal in (S.quotas.principals || {})) {
    const old = cloneQ(S.quotas);
    delete old.principals[oldPrincipal];
    const rq = await saveQuotas(old, comment);
    if (!rq.ok) note = " The old principal's limit was not removed: " + rq.message;
  }
  status((r.status === 202 ? "Saved as proposal #" + r.body.proposal.id + ": another admin must approve it before it takes effect." : "Saved as policy version " + r.body.version + ".") + note);
  loaded.overview = false; loaded.limits = false;
  renderWorkloads();
}

// ---- Agent limits: people only ----
const inputOf = k => $("ld-" + (k === "timeout_seconds" ? "timeout" : k));
function agentTable() {
  const Q = S.quotas, d = Q.defaults || {}, b = Q.built_in || {};
  const names = Object.keys(Q.people || {}).filter(p => AGENT.some(([k]) => Q.people[p][k] != null)).sort();
  const row = p => {
    const isDef = p === "default", pipe = !isDef && isPipeline(p);
    const e = isDef ? Object.fromEntries(AGENT.map(([k]) => [k, d[k] != null ? [d[k], "own"] : [b[k], "built-in"]])) : null;
    const cells = AGENT.map(([k]) => {
      const [v, src] = isDef ? e[k] : Q.people[p][k] != null ? [Q.people[p][k], "own"] : d[k] != null ? [d[k], "default"] : [b[k], "built-in"];
      return el("td", { class: "n" }, v == null ? el("span", { class: "s", text: "not set" }) : showValue(k, v), src === "own" ? null : el("span", { class: "sub", text: SOURCE[src] }));
    });
    return el("tr", { "data-who": p }, el("td", {}, el("strong", { text: isDef ? "Everyone (default)" : p }), isDef ? null : kindTag(p),
      pipe ? el("span", { class: "tag bad", text: "not applied: a workload has no managed agent" }) : null), ...cells,
      el("td", {}, el("button", { text: "Edit", "aria-label": "Edit agent limits for " + (isDef ? "everyone" : p), on: { click: () => openLimits(p) } })));
  };
  $("lm-table").replaceChildren(el("tr", {}, el("th", { text: "Applies to" }), ...AGENT.map(([, h]) => el("th", { class: "n", text: h })), el("th")), row("default"), ...names.map(row));
  const t = Q.technical || {};
  $("lm-tech").textContent = "What the system can serve, whatever is set: context window at most " + int(t.max_context) + " tokens (a 1 MiB request); timeout at most " +
    int(t.max_timeout_seconds) + " s (the broker ends every model call at " + int(t.max_timeout_seconds + 1) + " s). Built-in values are the agent's own, used where nothing is set.";
}
let limitsFor = null;
function openLimits(p) {
  limitsFor = p || null;
  const Q = S.quotas, d = Q.defaults || {}, b = Q.built_in || {}, t = Q.technical || {}, own = !p ? {} : p === "default" ? d : (Q.people || {})[p] || {};
  $("ld-title").textContent = !p ? "Set agent limits for a person" : p === "default" ? "Agent limits for everyone (default)" : "Agent limits for " + p;
  $("ld-who-field").hidden = !!p; $("ld-who").value = ""; $("ld-who").required = !p;
  for (const [k] of AGENT) {
    const i = inputOf(k);
    i.value = own[k] == null ? "" : String(own[k]);
    i.placeholder = p !== "default" && d[k] != null ? "default " + int(d[k]) : b[k] != null ? "built-in " + int(b[k]) : "";
  }
  $("ld-context").max = String(t.max_context || ""); $("ld-timeout").max = String(t.max_timeout_seconds || "");
  $("ld-context-help").textContent = "The agent compacts its history when it reaches this. 1 to " + int(t.max_context) + ".";
  $("ld-timeout-help").textContent = "The agent gives up on one model call after this and may retry. 1 to " + int(t.max_timeout_seconds) + ".";
  $("ld-tech").textContent = $("lm-tech").textContent;
  const self = () => { $("ld-self").hidden = !isMine(limitsFor || $("ld-who").value.trim()); };
  $("ld-who").oninput = self; self();
  $("ld-reason").value = ""; $("ld-msg").textContent = "";
  $("ld").showModal();
}
async function submitLimits() {
  const target = limitsFor || $("ld-who").value.trim();
  if (!target) { $("ld-msg").textContent = "Say who the limits are for."; return; }
  if (isPipeline(target)) { $("ld-msg").textContent = "Agent limits are for people only: a workload calls the models directly, with no managed agent. Set its spend and output limits instead."; return; }
  const q = cloneQ(S.quotas);
  for (const [k] of AGENT) {
    const v = inputOf(k).value;
    setLimit(q, target, k, v === "" ? null : Number(v));
  }
  $("ld-msg").textContent = "Saving…";
  const r = await saveQuotas(q, $("ld-reason").value.trim());
  if (!r.ok) { $("ld-msg").textContent = r.message; return; }
  $("ld").close(); status("Saved as version " + S.quotas.version + ". It applies to new sessions.");
  renderLimits();
}

const RENDER = { overview: renderOverview, usage: renderUsage, workloads: renderWorkloads, limits: renderLimits };

// Each dialog's form: Cancel (or Escape) closes it; Save, or Enter in a field, runs its submit,
// and the dialog stays open on an error.
function dialog(id, submit) {
  $(id + "-cancel").addEventListener("click", () => $(id).close());
  $(id + "-form").addEventListener("submit", e => { e.preventDefault(); submit(); });
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  dialog("qd", submitQuota); dialog("wd", submitWorkload); dialog("ld", submitLimits);
  $("qt-new").addEventListener("click", () => openQuota(null, "monthly_usd"));
  $("wl-new").addEventListener("click", () => openWorkload(null));
  $("lm-new").addEventListener("click", () => openLimits(null));
  for (const id of ["ov-uncapped", "lt-uncapped"]) $(id).querySelector("button").addEventListener("click", setDefault);
  $("lk-form").addEventListener("submit", e => { e.preventDefault(); lookup(); });
  for (const id of ["us-range", "us-kind", "us-model", "us-from", "us-to"]) $(id).addEventListener("change", renderUsage);
  $("us-search").addEventListener("input", usageTable);
  $("us-csv").addEventListener("click", usageCSV);
  $("us-csv-days").addEventListener("click", dailyCSV);
  show(location.hash.slice(1) || "overview");
});
