import { FEEDS } from "./feeds";
import type { FeedConfig, SyncResult } from "./types";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const BUILTIN_FEED_NAMES: Record<string, string> = {
  urlhaus_urls: "Abuse.ch URLhaus",
  openphish_urls: "OpenPhish",
  vxvault_urls: "VXVault",
  threatfox_domains: "Abuse.ch ThreatFox",
  certpl_phishing: "CERT.PL Phishing",
  malwaredomains: "URLhaus Domains",
  oisd_big: "OISD Big",
  hagezi_threat: "Hagezi TIF",
};

const BUILTIN_DOMAIN_FEED_IDS = [
  "threatfox_domains",
  "certpl_phishing",
  "malwaredomains",
  "oisd_big",
  "hagezi_threat",
];

const BUILTIN_URL_FEED_IDS = ["urlhaus_urls", "openphish_urls", "vxvault_urls"];

function feedSettingsRows(cfg: FeedConfig): string {
  const all = [
    ...FEEDS.map((f) => ({ ...f, custom: false })),
    ...cfg.custom.map((f) => ({ ...f, custom: true })),
  ];
  return all
    .map((f) => {
      const enabled = !cfg.disabled.includes(f.id);
      return `          <tr>
            <td><input type="checkbox" ${enabled ? "checked" : ""} class="switch" onchange="toggleFeed(this, '${f.id}')" aria-label="Enable ${esc(f.name)}"/></td>
            <td><span class="badge badge-${f.listType}">${f.listType.toUpperCase()}</span></td>
            <td>${esc(f.name)}${f.custom ? '<span class="custom-tag">custom</span>' : ""}</td>
            <td class="td-list">${f.listType === "url" ? "IOC_URL" : "IOC_DNS"}</td>
            <td class="td-actions">${f.custom ? `<button class="btn-icon" onclick="removeCustomFeed('${f.id}')">Remove</button>` : ""}</td>
          </tr>`;
    })
    .join("\n");
}

// The six real phases of runSync — rendered as the pipeline trace. The same
// markup doubles as the how-it-works diagram (Overview) and as the live
// progress indicator (Terminal), where markStep() lights nodes up as
// "STEP n" lines arrive in the stream.
const TRACE_STEPS: [string, string][] = [
  ["Fetch", "all feeds in parallel"],
  ["Partition", "hostname / URL buckets"],
  ["Read lists", "current Gateway contents"],
  ["Diff", "add + remove sets"],
  ["Intel check", "skip known threats"],
  ["Apply", "PATCH Gateway lists"],
];

function traceHtml(live: boolean): string {
  return `<ol class="trace">${TRACE_STEPS.map(
    (s, i) =>
      `<li class="tnode"${live ? ` id="step-${i + 1}"` : ""}><span class="tdot"></span><span class="tname">${s[0]}</span><span class="tcap">${s[1]}</span></li>`,
  ).join("")}</ol>`;
}

export function renderDashboard(lastSync: SyncResult | null, cfg: FeedConfig = { disabled: [], custom: [] }): string {
  const ts = lastSync
    ? new Date(lastSync.ts).toLocaleString("en-GB", { timeZone: "Asia/Bangkok", hour12: false })
    : "Never";
  const elapsed = lastSync ? `${(lastSync.elapsedMs / 1e3).toFixed(1)}s` : "\u2014";
  const domainCount = (lastSync?.domains.total ?? 0).toLocaleString();
  const urlCount = (lastSync?.urls.total ?? 0).toLocaleString();
  const customDomainIds = cfg.custom.filter((f) => f.listType === "domain").map((f) => f.id);
  const customUrlIds = cfg.custom.filter((f) => f.listType === "url").map((f) => f.id);
  const domainFeeds = Object.entries(lastSync?.feedStats ?? {}).filter(
    ([id]) => BUILTIN_DOMAIN_FEED_IDS.includes(id) || customDomainIds.includes(id),
  );
  const urlFeeds = Object.entries(lastSync?.feedStats ?? {}).filter(
    ([id]) => BUILTIN_URL_FEED_IDS.includes(id) || customUrlIds.includes(id),
  );
  const feedNames: Record<string, string> = {
    ...BUILTIN_FEED_NAMES,
    ...Object.fromEntries(cfg.custom.map((f) => [f.id, f.name])),
  };
  const allFeedCounts = [
    ...domainFeeds.map(([id, count]) => ({ id, count, type: "domain" })),
    ...urlFeeds.map(([id, count]) => ({ id, count, type: "url" })),
  ];
  const feedTableRows = allFeedCounts.length
    ? allFeedCounts
        .map(
          (r) => `
          <tr>
            <td>${esc(feedNames[r.id] ?? r.id)}</td>
            <td><span class="badge badge-${r.type}">${r.type.toUpperCase()}</span></td>
            <td class="count">${r.count.toLocaleString()}</td>
          </tr>`,
        )
        .join("")
    : `<tr><td colspan="3" class="empty">No data yet \u2014 run a sync</td></tr>`;
  const errors = lastSync?.feedErrors ?? [];
  const errHtml = errors.length
    ? `<div class="errors"><div class="err-title">Feed errors (${errors.length})</div>${errors
        .map((e) => `<div class="err-item">${esc(e)}</div>`)
        .join("")}</div>`
    : "";
  const health = errors.length
    ? `<span class="dot dot-err"></span>${errors.length} feed error${errors.length === 1 ? "" : "s"}`
    : `<span class="dot dot-ok"></span>all feeds healthy`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta name="theme-color" content="#1D1D1F"/>
  <meta name="description" content="Syncs OSINT threat-intelligence feeds into Cloudflare Zero Trust Gateway lists."/>
  <title>TI IOC Sync \u00B7 Gateway list ops</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%23F6821F' d='M7.2 18.6a4.3 4.3 0 0 1-.1-8.6 5.7 5.7 0 0 1 11.1-1.3 4 4 0 0 1-.4 7.9z'/%3E%3C/svg%3E"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet"/>
  <style>
    :root {
      --bg: #1D1D1F; --panel: #242529; --panel-2: #2B2C31; --console: #141518;
      --border: #33353B; --border-2: #3F4148;
      --text: #F7F7F8; --text-2: #AFB2BB; --text-3: #7A7D85;
      --orange: #F6821F; --orange-2: #FBAD41;
      --ok: #4CAF74; --err: #ED4C5C; --blue: #74A9FF;
      --font-ui: 'Inter', -apple-system, 'Segoe UI', sans-serif;
      --font-display: 'Space Grotesk', 'Inter', sans-serif;
      --font-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', monospace;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { color-scheme: dark; }
    body { background: var(--bg); color: var(--text); font: 14px/1.5 var(--font-ui); padding-bottom: 72px; }
    [hidden] { display: none !important; }
    :focus-visible { outline: 2px solid var(--orange); outline-offset: 2px; border-radius: 2px; }
    a { color: var(--blue); text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* \u2500 Top bar \u2500 */
    .topbar { position: sticky; top: 0; z-index: 20; background: rgba(29,29,31,.94); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); }
    .topbar-in { max-width: 1120px; margin: 0 auto; padding: 0 24px; height: 56px; display: flex; align-items: center; gap: 22px; }
    .brand { display: flex; align-items: center; gap: 10px; margin-right: auto; min-width: 0; }
    .brand .mark { width: 24px; height: 24px; flex: none; }
    .brand-text { line-height: 1.15; }
    .brand-name { font: 700 15px var(--font-display); letter-spacing: -.01em; white-space: nowrap; }
    .brand-sub { font: 500 10.5px var(--font-ui); color: var(--text-3); white-space: nowrap; }
    .tabs { display: flex; gap: 2px; }
    .tab { appearance: none; background: none; border: 0; cursor: pointer; color: var(--text-2); font: 600 13px var(--font-ui); padding: 7px 14px; border-radius: 999px; transition: color .15s, background .15s; }
    .tab:hover { color: var(--text); }
    .tab.active { background: var(--panel-2); color: var(--text); }
    .clock { font: 600 12px var(--font-mono); color: var(--text-2); white-space: nowrap; }
    .clock small { color: var(--text-3); font-size: 10px; font-weight: 400; }

    /* \u2500 Layout \u2500 */
    main { max-width: 1120px; margin: 0 auto; padding: 26px 24px 0; }
    .panel-title { font: 600 20px var(--font-display); letter-spacing: -.01em; margin-bottom: 6px; }
    .panel-sub { color: var(--text-2); font-size: 13px; margin-bottom: 18px; max-width: 70ch; }

    /* \u2500 Hero \u2500 */
    .hero { font: 700 clamp(28px, 4.6vw, 42px)/1.15 var(--font-display); letter-spacing: -.02em; margin-bottom: 10px; }
    .hero .num { color: var(--orange); font-variant-numeric: tabular-nums; }
    .hero-sub { color: var(--text-2); font-size: 13px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 2px; }
    .dot-ok { background: var(--ok); }
    .dot-err { background: var(--err); }

    /* \u2500 Actions \u2500 */
    .actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 20px 0 18px; }
    .btn { appearance: none; border: 0; cursor: pointer; font: 600 13px var(--font-ui); border-radius: 5px; padding: 9px 16px; transition: background .15s, border-color .15s; display: inline-flex; align-items: center; gap: 7px; }
    .btn:disabled { opacity: .55; cursor: not-allowed; }
    .btn-primary { background: var(--orange); color: #17181A; font-weight: 700; }
    .btn-primary:hover { background: var(--orange-2); }
    .btn-ghost { background: transparent; border: 1px solid var(--border-2); color: var(--text); }
    .btn-ghost:hover { background: var(--panel-2); }
    .status { font-size: 12.5px; color: var(--text-2); min-height: 1em; }

    /* \u2500 Cards \u2500 */
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 18px; overflow: hidden; }
    .card-head { padding: 14px 16px 10px; display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; }
    .card-title { font: 600 13.5px var(--font-display); }
    .card-note { font-size: 11.5px; color: var(--text-3); }
    .card-body { padding: 4px 16px 14px; }
    .card-foot { padding: 10px 16px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-3); line-height: 1.6; }
    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }

    /* \u2500 Tables \u2500 */
    table { width: 100%; border-collapse: collapse; }
    th { font: 600 10.5px var(--font-ui); text-transform: uppercase; letter-spacing: .07em; color: var(--text-3); text-align: left; padding: 9px 16px; border-bottom: 1px solid var(--border); }
    td { padding: 9px 16px; font-size: 13px; border-bottom: 1px solid rgba(51,53,59,.55); vertical-align: middle; }
    tr:last-child td { border-bottom: 0; }
    tbody tr:hover td { background: var(--panel-2); }
    td.count { font: 600 13px var(--font-mono); font-variant-numeric: tabular-nums; text-align: right; }
    td.empty { color: var(--text-3); text-align: center; padding: 22px; }
    td.td-list { color: var(--text-2); font-family: var(--font-mono); font-size: 12px; }
    td.td-actions { text-align: right; }

    /* \u2500 Badges \u2500 */
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font: 700 10px var(--font-ui); letter-spacing: .06em; text-transform: uppercase; }
    .badge-domain { background: rgba(76,175,116,.14); color: #7ED9A0; border: 1px solid rgba(76,175,116,.3); }
    .badge-url { background: rgba(116,169,255,.14); color: #9CC0FF; border: 1px solid rgba(116,169,255,.3); }
    .custom-tag { font: 700 9px var(--font-ui); letter-spacing: .06em; text-transform: uppercase; background: rgba(139,92,246,.16); color: #B79BF8; border: 1px solid rgba(139,92,246,.32); border-radius: 4px; padding: 1px 6px; margin-left: 8px; vertical-align: middle; }
    .badge-manual { display: inline-block; font: 700 9px var(--font-ui); letter-spacing: .06em; text-transform: uppercase; background: rgba(139,92,246,.16); color: #B79BF8; border: 1px solid rgba(139,92,246,.32); border-radius: 4px; padding: 1px 6px; margin-left: 8px; vertical-align: middle; }
    .item-value { font: 12.5px var(--font-mono); word-break: break-all; }

    /* \u2500 Errors banner \u2500 */
    .errors { background: rgba(237,76,92,.07); border: 1px solid rgba(237,76,92,.28); border-radius: 8px; padding: 12px 16px; margin-bottom: 18px; }
    .err-title { font: 600 13px var(--font-ui); color: var(--err); margin-bottom: 6px; }
    .err-item { font: 12px/1.65 var(--font-mono); color: #F1939D; word-break: break-all; }

    /* \u2500 Trace (pipeline signature) \u2500 */
    .trace { list-style: none; display: flex; padding: 6px 2px 2px; }
    .tnode { flex: 1; min-width: 92px; position: relative; text-align: center; padding: 0 6px; }
    .tnode::after { content: ""; position: absolute; top: 5px; left: calc(-50% + 12px); width: calc(100% - 24px); border-top: 2px solid var(--border); }
    .tnode:first-child::after { display: none; }
    .tdot { display: block; width: 10px; height: 10px; border-radius: 50%; background: var(--panel-2); border: 2px solid var(--border-2); margin: 0 auto 8px; position: relative; z-index: 1; transition: background .2s, border-color .2s; }
    .tname { display: block; font: 600 12.5px var(--font-ui); }
    .tcap { display: block; font-size: 11px; color: var(--text-3); margin-top: 2px; line-height: 1.4; }
    .tnode.done .tdot { background: var(--orange); border-color: var(--orange); }
    .tnode.done::after { border-color: var(--orange); }
    .tnode.active .tdot { background: var(--orange); border-color: var(--orange); animation: tpulse 1.4s ease-in-out infinite; }
    @keyframes tpulse { 50% { box-shadow: 0 0 0 6px rgba(246,130,31,.14); } }

    /* \u2500 Forms \u2500 */
    .add-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; padding: 14px 16px; border-top: 1px solid var(--border); }
    .add-row input[type=text] { background: var(--bg); border: 1px solid var(--border-2); border-radius: 5px; color: var(--text); font: 12.5px var(--font-mono); padding: 9px 12px; }
    .add-row input[type=text]:focus { border-color: var(--orange); outline: none; }
    .add-row select { background: var(--bg); border: 1px solid var(--border-2); border-radius: 5px; color: var(--text); font: 13px var(--font-ui); padding: 9px 10px; }
    #custom-url { flex: 1 1 240px; }
    #item-input { flex: 1 1 220px; }
    #item-search { flex: 0 1 150px; }
    .hint { width: 100%; font-size: 11.5px; color: var(--text-3); line-height: 1.6; }
    .hint b { color: var(--text-2); }

    /* \u2500 Switches \u2500 */
    .switch { appearance: none; width: 34px; height: 20px; border-radius: 999px; background: var(--border-2); position: relative; cursor: pointer; transition: background .15s; display: inline-block; vertical-align: middle; }
    .switch::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: #fff; transition: left .15s; }
    .switch:checked { background: var(--orange); }
    .switch:checked::after { left: 16px; }

    /* \u2500 Buttons in tables \u2500 */
    .btn-icon { appearance: none; cursor: pointer; background: rgba(237,76,92,.1); border: 1px solid rgba(237,76,92,.3); color: var(--err); font: 600 11px var(--font-ui); border-radius: 4px; padding: 4px 10px; }
    .btn-icon:hover { background: rgba(237,76,92,.2); }

    /* \u2500 List manager \u2500 */
    .listbar { padding: 12px 16px 4px; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    .listbar .tabs { gap: 4px; }
    .count-pill { font: 600 12px var(--font-mono); font-variant-numeric: tabular-nums; background: var(--panel-2); border: 1px solid var(--border-2); border-radius: 999px; padding: 2px 12px; color: var(--text); }
    .pager { display: flex; justify-content: center; align-items: center; gap: 14px; padding: 10px; border-top: 1px solid var(--border); font: 12px var(--font-mono); color: var(--text-2); }
    .pager button { appearance: none; cursor: pointer; background: var(--panel-2); border: 1px solid var(--border-2); color: var(--text); border-radius: 4px; font: 600 12px var(--font-ui); padding: 4px 12px; }
    .pager button:disabled { opacity: .4; cursor: not-allowed; }

    /* \u2500 Terminal \u2500 */
    .termbar { display: flex; align-items: center; gap: 14px; margin-bottom: 14px; flex-wrap: wrap; }
    #stream-blink { display: none; width: 8px; height: 8px; border-radius: 50%; background: var(--orange); animation: tpulse 1.2s infinite; }
    #stream-label { font: 600 11px var(--font-mono); letter-spacing: .08em; color: var(--text-2); }
    .console-wrap { background: var(--console); border: 1px solid var(--border); border-radius: 8px; }
    #matrix-term { height: 440px; overflow-y: auto; padding: 16px 18px; font: 12.5px/1.65 var(--font-mono); color: #C6CAD2; scroll-behavior: smooth; }
    .ml { display: block; white-space: pre-wrap; word-break: break-all; }
    .ml-dim { color: #4E5158; }
    .ml-head { color: var(--orange); font-weight: 600; }
    .ml-step { color: var(--orange-2); font-weight: 600; }
    .ml-error { color: var(--err); }
    .ml-done { color: var(--ok); font-weight: 600; }
    .ml-intel { color: var(--blue); }
    .ml-add { color: var(--ok); }
    .ml-remove { color: #FF8A5C; }

    /* \u2500 Code blocks \u2500 */
    .code { background: var(--console); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font: 12.5px/1.7 var(--font-mono); color: var(--text); }
    .code .var { color: var(--orange-2); font-weight: 600; }
    .policy-label { font: 700 10.5px var(--font-ui); text-transform: uppercase; letter-spacing: .06em; color: var(--text-3); margin-bottom: 8px; }
    .policy-desc { font-size: 12px; color: var(--text-3); margin-top: 8px; }

    /* \u2500 Footer \u2500 */
    .foot { max-width: 1120px; margin: 30px auto 0; padding: 0 24px; color: var(--text-3); font-size: 12px; display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
    .foot .sep { color: var(--border-2); }

    .noscript { max-width: 1120px; margin: 16px auto 0; padding: 10px 16px; border: 1px solid rgba(251,173,65,.35); background: rgba(251,173,65,.08); color: var(--orange-2); border-radius: 8px; font-size: 13px; }

    @media (max-width: 780px) {
      .topbar-in { flex-wrap: wrap; height: auto; padding: 10px 16px; gap: 8px 12px; }
      .clock { display: none; }
      .tabs { order: 3; width: 100%; overflow-x: auto; padding-bottom: 2px; }
      main { padding: 20px 16px 0; }
      .grid2 { grid-template-columns: 1fr; }
      .trace { flex-wrap: wrap; gap: 10px 0; }
      .tnode { min-width: 33%; }
      .tnode::after { display: none; }
      #matrix-term { height: 320px; }
    }
    @media (prefers-reduced-motion: reduce) {
      * { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
    }
  </style>
</head>
<body>

<header class="topbar">
  <div class="topbar-in">
    <div class="brand">
      <svg class="mark" viewBox="0 0 24 24" aria-hidden="true">
        <defs>
          <linearGradient id="cf-grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#FAAE40"/>
            <stop offset=".55" stop-color="#F6821F"/>
            <stop offset="1" stop-color="#E8590C"/>
          </linearGradient>
        </defs>
        <path fill="url(#cf-grad)" d="M7.2 18.6a4.3 4.3 0 0 1-.1-8.6 5.7 5.7 0 0 1 11.1-1.3 4 4 0 0 1-.4 7.9z"/>
      </svg>
      <div class="brand-text">
        <span class="brand-name">TI IOC Sync</span>
        <span class="brand-sub">Zero Trust Gateway lists</span>
      </div>
    </div>
    <nav class="tabs" role="tablist" aria-label="Sections">
      <button class="tab active" id="nav-overview" role="tab" aria-selected="true" onclick="showTab('overview')">Overview</button>
      <button class="tab" id="nav-feeds" role="tab" aria-selected="false" onclick="showTab('feeds')">Feeds</button>
      <button class="tab" id="nav-lists" role="tab" aria-selected="false" onclick="showTab('lists')">Lists</button>
      <button class="tab" id="nav-terminal" role="tab" aria-selected="false" onclick="showTab('terminal')">Terminal</button>
    </nav>
    <div class="clock"><span id="clock">--:--:--</span> <small>ICT</small></div>
  </div>
</header>

<noscript><div class="noscript">The dashboard needs JavaScript for syncs, feed settings, and list management. The status below is live from the last sync.</div></noscript>

<main>

  <!-- \u2500\u2500 Overview \u2500\u2500 -->
  <section id="panel-overview" role="tabpanel" aria-label="Overview">
    <h1 class="hero">Blocking <span class="num">${domainCount}</span> hostnames <span aria-hidden="true">\u00B7</span> <span class="num">${urlCount}</span> full URLs</h1>
    <p class="hero-sub">Last sync ${ts} \u00B7 ${elapsed} \u00B7 ${health}</p>

    <div class="actions">
      <button class="btn btn-primary" id="sync-btn" onclick="triggerSync()">Run sync</button>
      <button class="btn btn-ghost" onclick="showTab('terminal'); toggleStream()">\u25B6 Stream live sync</button>
      <button class="btn btn-ghost" onclick="location.reload()">Refresh</button>
      <span class="status" id="sync-status"></span>
    </div>

    ${errHtml}

    <div class="card">
      <div class="card-head">
        <span class="card-title">Feed contribution</span>
        <span class="card-note">items from the last sync</span>
      </div>
      <table>
        <thead><tr><th>Feed</th><th>Type</th><th style="text-align:right">Items</th></tr></thead>
        <tbody>${feedTableRows}
        </tbody>
      </table>
      <div class="card-foot">+${lastSync?.domains.added ?? 0}/-${lastSync?.domains.removed ?? 0} domains and +${lastSync?.urls.added ?? 0}/-${lastSync?.urls.removed ?? 0} URLs this cycle \u00B7 ${lastSync?.domains.intelSkipped ?? 0} domains skipped by Intel dedup \u00B7 5,000-item cap per list</div>
    </div>

    <div class="card">
      <div class="card-head"><span class="card-title">Sync pipeline</span></div>
      <div class="card-body">${traceHtml(false)}</div>
      <div class="card-foot">Runs daily at 08:00 UTC. Removals are fail-closed \u2014 if a feed is broken or empty, stale items are left alone instead of unblocked.</div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Policy wiring</span>
        <span class="card-note">reference the lists in Gateway policies</span>
      </div>
      <div class="card-body">
        <div class="grid2">
          <div>
            <div class="policy-label">DNS policy</div>
            <code class="code">dns.fqdn in <span class="var">$IOC_DNS</span></code>
            <p class="policy-desc">Blocks resolution of malicious hostnames before a connection is made.</p>
          </div>
          <div>
            <div class="policy-label">HTTP policy</div>
            <code class="code">http.request.host.host in <span class="var">$IOC_DNS</span><br>OR http.request.full_uri in <span class="var">$IOC_URL</span></code>
            <p class="policy-desc">Blocks requests by hostname, and specific full URLs (path-aware).</p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- \u2500\u2500 Feeds \u2500\u2500 -->
  <section id="panel-feeds" role="tabpanel" aria-label="Feed settings" hidden>
    <h2 class="panel-title">Feed Settings</h2>
    <p class="panel-sub">Toggles apply on the next sync. Items from a feed return as long as the feed still lists them \u2014 disable a feed to drop its items for good.</p>

    <div class="card">
      <table>
        <thead><tr><th>Enabled</th><th>Type</th><th>Feed</th><th>List</th><th></th></tr></thead>
        <tbody>
${feedSettingsRows(cfg)}
        </tbody>
      </table>
      <div class="add-row">
        <input type="text" id="custom-url" placeholder="https://example.com/blocklist.txt" spellcheck="false" aria-label="Custom feed URL"/>
        <select id="custom-type" aria-label="Custom feed type">
          <option value="domain">Hostnames (IOC_DNS)</option>
          <option value="url">Full URLs (IOC_URL)</option>
        </select>
        <button class="btn btn-primary" onclick="addCustomFeed()">Add feed</button>
        <span class="status" id="feed-status"></span>
        <div class="hint">Only <b>.txt</b> plain-text lists are accepted \u2014 one hostname or URL per line, # comments allowed. Custom feeds are capped at 500 items each (max 10). IP-literal, localhost, and credential-bearing URLs are rejected. Admin actions ask for the <b>ADMIN_TOKEN</b> secret once per tab session.</div>
      </div>
    </div>
  </section>

  <!-- \u2500\u2500 Lists \u2500\u2500 -->
  <section id="panel-lists" role="tabpanel" aria-label="Gateway list items" hidden>
    <h2 class="panel-title">Gateway list items</h2>
    <p class="panel-sub">Manual items are stored in KV and survive syncs. Feed-sourced items return on the next sync \u2014 disable the feed on the Feeds tab to drop them permanently. Whitelisted hostnames are rejected; the 5,000-item cap applies.</p>

    <div class="card">
      <div class="listbar">
        <div class="tabs">
          <button class="tab active" id="tab-domain" onclick="switchListTab('domain')">IOC_DNS \u00B7 hostnames</button>
          <button class="tab" id="tab-url" onclick="switchListTab('url')">IOC_URL \u00B7 full URLs</button>
        </div>
        <span class="count-pill" id="items-count">\u2014</span>
      </div>
      <div class="add-row">
        <input type="text" id="item-input" placeholder="example.com (comma/newline separated for multiple)" spellcheck="false" aria-label="Items to add"/>
        <button class="btn btn-primary" onclick="addListItems()">Add</button>
        <input type="text" id="item-search" placeholder="Search\u2026" oninput="renderItemsTable()" spellcheck="false" aria-label="Search items"/>
        <button class="btn btn-ghost" onclick="loadListItems()">\u21BB Load / Refresh</button>
        <span class="status" id="items-status"></span>
      </div>
      <table>
        <thead><tr><th>Value</th><th style="text-align:right;width:100px"></th></tr></thead>
        <tbody id="items-tbody"><tr><td colspan="2" class="empty">Press \u21BB Load / Refresh to view items (requires the admin token)</td></tr></tbody>
      </table>
      <div class="pager">
        <button id="items-prev" onclick="itemsPage(-1)" disabled>\u2039 Prev</button>
        <span id="items-page-info">\u2013</span>
        <button id="items-next" onclick="itemsPage(1)" disabled>Next \u203A</button>
      </div>
    </div>
  </section>

  <!-- \u2500\u2500 Terminal \u2500\u2500 -->
  <section id="panel-terminal" role="tabpanel" aria-label="Live sync terminal" hidden>
    <h2 class="panel-title">Live sync</h2>
    <p class="panel-sub">Watch a full sync run end-to-end. The trace below follows each STEP as it happens; removals skip while any feed is broken.</p>

    <div class="termbar">
      <button class="btn btn-primary" id="stream-btn" onclick="toggleStream()">\u25B6 Stream live sync</button>
      <span id="stream-blink"></span>
      <span id="stream-label">READY</span>
    </div>

    <div class="card">
      <div class="card-body">${traceHtml(true)}</div>
    </div>

    <div class="console-wrap">
      <div id="matrix-term"><span class="ml ml-dim">Press \u25B6 Stream live sync to start a run.</span></div>
    </div>
  </section>

</main>

<footer class="foot">
  <span>TI IOC Sync</span><span class="sep">\u00B7</span>
  <span>runs on Cloudflare Workers</span><span class="sep">\u00B7</span>
  <span>syncs daily at 08:00 UTC</span><span class="sep">\u00B7</span>
  <a href="/api/status">JSON status</a><span class="sep">\u00B7</span>
  <a href="https://github.com/pongpisit/cloudflare-ti-ioc-sync" target="_blank" rel="noopener">source on GitHub</a>
</footer>

<script>
// \u2500\u2500 Navigation \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
function showTab(name) {
  var names = ['overview', 'feeds', 'lists', 'terminal'];
  for (var i = 0; i < names.length; i++) {
    var p = document.getElementById('panel-' + names[i]);
    var b = document.getElementById('nav-' + names[i]);
    var on = names[i] === name;
    if (p) p.hidden = !on;
    if (b) {
      b.className = on ? 'tab active' : 'tab';
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    }
  }
}

function tickClock() {
  var el = document.getElementById('clock');
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString('en-GB', { timeZone: 'Asia/Bangkok', hour12: false });
}
tickClock();
setInterval(tickClock, 1000);

// \u2500\u2500 Admin token \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// All mutating/admin endpoints require the ADMIN_TOKEN Worker secret, sent as the
// X-Auth-Token header. The token is kept in sessionStorage (per tab session only).
// NOTE: this is the dashboard admin token (wrangler secret put ADMIN_TOKEN), NOT the
// Cloudflare API token.
function getAdminToken() {
  let t = sessionStorage.getItem('ti_admin_token');
  while (!t) {
    t = prompt('Dashboard admin token required (set via: wrangler secret put ADMIN_TOKEN):');
    if (t === null) return null;
    t = t.trim();
    if (t) sessionStorage.setItem('ti_admin_token', t);
  }
  return t;
}

function handleAuthError(res) {
  if (res.status === 401 || res.status === 503) {
    sessionStorage.removeItem('ti_admin_token');
    return '\u274C Unauthorized \u2014 check the ADMIN_TOKEN secret';
  }
  return null;
}

async function authFetch(input, init) {
  const t = getAdminToken();
  if (t === null) throw new Error('admin token required');
  const headers = Object.assign({}, (init && init.headers) || {}, { 'X-Auth-Token': t });
  return fetch(input, Object.assign({}, init || {}, { headers: headers }));
}

// \u2500\u2500 Sync button \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async function triggerSync() {
  const btn = document.getElementById('sync-btn');
  const status = document.getElementById('sync-status');
  btn.disabled = true;
  btn.textContent = 'Syncing\u2026';
  status.textContent = '';
  try {
    // Inline request: the sync runs within the request lifetime. (Background
    // waitUntil tasks are cancelled ~30s after the response, so POST /sync
    // cannot carry a full sync.) If the edge proxy ever times the request
    // out, the live terminal still streams every step.
    const res = await authFetch('/sync/run', { method: 'POST' });
    const authErr = handleAuthError(res);
    if (authErr) { status.textContent = authErr; return; }
    if (!res.ok) {
      const data = await res.json().catch(function(){ return {}; });
      status.textContent = '\u274C ' + (data.error || 'HTTP ' + res.status + ' \u2014 try the live terminal instead');
      return;
    }
    const data = await res.json();
    if (data.status === 'ok') {
      const r = data.result;
      status.textContent = '\u2705 Done \u2014 hostnames +' + r.domains.added + '/-' + r.domains.removed + '=' + r.domains.total +
                          '  URLs +' + r.urls.added + '/-' + r.urls.removed + '=' + r.urls.total;
      setTimeout(function(){ location.reload(); }, 2500);
    } else {
      status.textContent = '\u274C ' + (data.error || 'Unknown error');
    }
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
  }
  btn.disabled = false;
  btn.textContent = 'Run sync';
}

// \u2500\u2500 Live terminal \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
let streamController = null;
let streamOpen = false;

function toggleStream() {
  if (streamOpen) {
    stopStream();
  } else {
    openStream();
  }
}

function openStream() {
  const term  = document.getElementById('matrix-term');
  const btn   = document.getElementById('stream-btn');
  const blink = document.getElementById('stream-blink');
  const label = document.getElementById('stream-label');
  const t = getAdminToken();
  if (t === null) {
    label.textContent = 'TOKEN REQUIRED';
    return;
  }

  term.innerHTML = '';
  btn.textContent = '\u23F9 Stop stream';
  blink.style.display = 'inline-block';
  label.textContent = 'STREAMING';
  streamOpen = true;
  for (var k = 1; k <= 6; k++) {
    var e2 = document.getElementById('step-' + k);
    if (e2) e2.className = 'tnode';
  }

  streamController = new AbortController();

  fetch('/sync/stream', { signal: streamController.signal, headers: { 'X-Auth-Token': t } })
    .then(res => {
      if (res.status === 401 || res.status === 503) {
        sessionStorage.removeItem('ti_admin_token');
        appendLine(term, '[ERROR] Unauthorized \u2014 check the ADMIN_TOKEN secret');
        label.textContent = 'UNAUTHORIZED';
        blink.style.display = 'none';
        btn.textContent = '\u25B6 Stream live sync';
        streamOpen = false;
        return;
      }
      const reader = res.body.getReader();
      const dec    = new TextDecoder();
      let   buf    = '';

      function pump() {
        return reader.read().then(({ done, value }) => {
          if (done) {
            // flush remaining buffer
            if (buf.trim()) appendLine(term, buf);
            label.textContent = 'DONE';
            blink.style.display = 'none';
            btn.textContent = '\u25B6 Stream live sync';
            streamOpen = false;
            return;
          }
          buf += dec.decode(value, { stream: true });
          const lines = buf.split('\\n');
          buf = lines.pop(); // keep incomplete line
          for (const line of lines) appendLine(term, line);
          return pump();
        });
      }
      return pump();
    })
    .catch(err => {
      if (err.name !== 'AbortError') {
        appendLine(term, '[ERROR] ' + err.message);
      }
      label.textContent = 'CLOSED';
      blink.style.display = 'none';
      btn.textContent = '\u25B6 Stream live sync';
      streamOpen = false;
    });
}

function stopStream() {
  if (streamController) streamController.abort();
  const btn   = document.getElementById('stream-btn');
  const blink = document.getElementById('stream-blink');
  const label = document.getElementById('stream-label');
  btn.textContent = '\u25B6 Stream live sync';
  blink.style.display = 'none';
  label.textContent = 'STOPPED';
  streamOpen = false;
}

// Lights the terminal trace as "STEP n" lines arrive in the stream.
function markStep(line) {
  if (line.indexOf('SYNC COMPLETE') >= 0) {
    for (var k = 1; k <= 6; k++) {
      var e = document.getElementById('step-' + k);
      if (e) e.className = 'tnode done';
    }
    return;
  }
  var i = line.indexOf('STEP ');
  if (i < 0) return;
  var n = parseInt(line.charAt(i + 5), 10);
  if (!n || n < 1 || n > 6) return;
  for (var k = 1; k <= 6; k++) {
    var e = document.getElementById('step-' + k);
    if (!e) continue;
    e.className = 'tnode' + (k < n ? ' done' : (k === n ? ' active' : ''));
  }
}

function appendLine(term, raw) {
  markStep(raw);
  const line = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const span = document.createElement('span');
  span.className = 'ml ' + classifyLine(raw);
  span.innerHTML = line || '&nbsp;';
  term.appendChild(span);
  // auto-scroll
  term.scrollTop = term.scrollHeight;
  // keep max 2000 lines to avoid memory growth
  while (term.children.length > 2000) term.removeChild(term.firstChild);
}

function classifyLine(line) {
  if (line.includes('\u2550\u2550\u2550'))            return 'ml-head';
  if (/STEP \\d/.test(line))           return 'ml-step';
  if (line.includes('[ERROR]'))        return 'ml-error';
  if (line.includes('SYNC COMPLETE'))  return 'ml-done';
  if (line.includes('Intel') || line.includes('intel')) return 'ml-intel';
  if (line.includes('\u2713 added') || line.startsWith('[') && line.includes('+ ')) return 'ml-add';
  if (line.includes('\u2713 removed') || line.includes('removing')) return 'ml-remove';
  if (line.includes('\u2197') || line.includes('\u2713') || line.includes('items')) return 'ml-feed';
  if (!line.trim())                    return 'ml-dim';
  return '';
}

// \u2500\u2500 Feed settings \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
const TXT_URL_RE = /^https?:\\/\\/[^\\s?#]+\\.txt([?#]\\S*)?$/i;

async function toggleFeed(cb, id) {
  const status = document.getElementById('feed-status');
  status.textContent = 'Saving\u2026';
  try {
    const res = await authFetch('/api/feeds/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id, enabled: cb.checked })
    });
    const authErr = handleAuthError(res);
    if (authErr) { status.textContent = authErr; cb.checked = !cb.checked; return; }
    const data = await res.json();
    if (data.status === 'ok') {
      status.textContent = (cb.checked ? '\u2705 Enabled: ' : '\u26D4 Disabled: ') + id + ' \u2014 applies on next sync';
    } else {
      status.textContent = '\u274C ' + (data.error || 'Failed to update feed');
      cb.checked = !cb.checked;
    }
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
    cb.checked = !cb.checked;
  }
}

async function addCustomFeed() {
  const input = document.getElementById('custom-url');
  const sel = document.getElementById('custom-type');
  const status = document.getElementById('feed-status');
  const url = input.value.trim();
  if (!TXT_URL_RE.test(url)) {
    status.textContent = '\u274C Only .txt URLs are accepted (e.g. https://example.com/list.txt)';
    return;
  }
  status.textContent = 'Adding\u2026';
  try {
    const res = await authFetch('/api/feeds/custom', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, listType: sel.value })
    });
    const authErr = handleAuthError(res);
    if (authErr) { status.textContent = authErr; return; }
    const data = await res.json();
    if (data.status === 'ok') {
      location.reload();
    } else {
      status.textContent = '\u274C ' + (data.error || 'Failed to add feed');
    }
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
  }
}

async function removeCustomFeed(id) {
  if (!confirm('Remove custom feed ' + id + '?')) return;
  try {
    const res = await authFetch('/api/feeds/custom/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id })
    });
    const authErr = handleAuthError(res);
    if (authErr) { document.getElementById('feed-status').textContent = authErr; return; }
    const data = await res.json();
    if (data.status === 'ok') {
      location.reload();
    } else {
      document.getElementById('feed-status').textContent = '\u274C ' + (data.error || 'Failed to remove feed');
    }
  } catch(e) {
    document.getElementById('feed-status').textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
  }
}

// \u2500\u2500 List items manager \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
let itemsState = { listType: 'domain', items: [], page: 0, perPage: 50 };

function switchListTab(t) {
  itemsState.listType = t;
  itemsState.items = [];
  itemsState.page = 0;
  document.getElementById('tab-domain').classList.toggle('active', t === 'domain');
  document.getElementById('tab-url').classList.toggle('active', t === 'url');
  document.getElementById('item-input').placeholder = t === 'domain'
    ? 'example.com (comma/newline separated for multiple)'
    : 'https://example.com/path (comma/newline separated for multiple)';
  document.getElementById('items-count').textContent = '\u2014';
  document.getElementById('items-page-info').textContent = '\u2013';
  document.getElementById('items-tbody').innerHTML =
    '<tr><td colspan="2" class="empty">Press \u21BB Load / Refresh to view items (requires the admin token)</td></tr>';
}

async function loadListItems() {
  const status = document.getElementById('items-status');
  const tbody = document.getElementById('items-tbody');
  tbody.innerHTML = '<tr><td colspan="2" class="empty">Loading\u2026</td></tr>';
  try {
    const res = await authFetch('/api/lists/items?list=' + itemsState.listType);
    const authErr = handleAuthError(res);
    if (authErr) {
      status.textContent = authErr;
      tbody.innerHTML = '<tr><td colspan="2" class="empty">Not loaded</td></tr>';
      return;
    }
    const data = await res.json();
    if (data.status !== 'ok') {
      status.textContent = '\u274C ' + (data.error || 'Failed to load');
      tbody.innerHTML = '<tr><td colspan="2" class="empty">Not loaded</td></tr>';
      return;
    }
    status.textContent = '';
    itemsState.items = data.items || [];
    itemsState.page = 0;
    document.getElementById('items-count').textContent = itemsState.items.length.toLocaleString() + ' items';
    renderItemsTable();
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
    tbody.innerHTML = '<tr><td colspan="2" class="empty">Not loaded</td></tr>';
  }
}

function renderItemsTable() {
  const tbody = document.getElementById('items-tbody');
  const search = (document.getElementById('item-search').value || '').trim().toLowerCase();
  const filtered = search
    ? itemsState.items.filter(function(i){ return i.value.toLowerCase().includes(search); })
    : itemsState.items;
  const per = itemsState.perPage;
  const pages = Math.max(1, Math.ceil(filtered.length / per));
  if (itemsState.page >= pages) itemsState.page = pages - 1;
  const slice = filtered.slice(itemsState.page * per, itemsState.page * per + per);
  tbody.innerHTML = '';
  if (!slice.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 2;
    td.className = 'empty';
    td.textContent = filtered.length ? 'No items on this page' : 'No items in this list';
    tr.appendChild(td);
    tbody.appendChild(tr);
  } else {
    for (const it of slice) {
      const tr = document.createElement('tr');
      const tdV = document.createElement('td');
      tdV.className = 'item-value';
      tdV.textContent = it.value;
      if (it.manual) {
        const b = document.createElement('span');
        b.className = 'badge-manual';
        b.textContent = 'manual';
        tdV.appendChild(b);
      }
      const tdA = document.createElement('td');
      tdA.className = 'td-actions';
      const btn = document.createElement('button');
      btn.className = 'btn-icon';
      btn.textContent = 'Remove';
      const val = it.value;
      const isManual = !!it.manual;
      btn.addEventListener('click', function() { removeListItem(val, isManual); });
      tdA.appendChild(btn);
      tr.appendChild(tdV);
      tr.appendChild(tdA);
      tbody.appendChild(tr);
    }
  }
  document.getElementById('items-prev').disabled = itemsState.page <= 0;
  document.getElementById('items-next').disabled = itemsState.page >= pages - 1;
  document.getElementById('items-page-info').textContent =
    (filtered.length ? itemsState.page + 1 : 0) + ' / ' + pages;
}

function itemsPage(delta) {
  itemsState.page += delta;
  renderItemsTable();
}

async function addListItems() {
  const input = document.getElementById('item-input');
  const status = document.getElementById('items-status');
  const values = input.value.split(/[\\n,;]+/).map(function(s){ return s.trim(); }).filter(Boolean);
  if (!values.length) {
    status.textContent = '\u274C Enter at least one value';
    return;
  }
  status.textContent = 'Adding\u2026';
  try {
    const res = await authFetch('/api/lists/items', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ list: itemsState.listType, items: values })
    });
    const authErr = handleAuthError(res);
    if (authErr) { status.textContent = authErr; return; }
    const data = await res.json();
    if (data.status === 'ok') {
      const skipped = data.skipped || [];
      status.textContent = '\u2705 Added ' + data.added +
        (skipped.length
          ? ' \u2014 skipped ' + skipped.length + ': ' +
            skipped.slice(0, 3).map(function(s){ return s.value + ' (' + s.reason + ')'; }).join('; ') +
            (skipped.length > 3 ? ' \u2026' : '')
          : '');
      input.value = '';
      loadListItems();
    } else {
      status.textContent = '\u274C ' + (data.error || 'Failed to add');
    }
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
  }
}

async function removeListItem(value, isManual) {
  const msg = isManual
    ? 'Remove ' + value + ' from the list?'
    : 'Remove ' + value + ' from the list?\\n\\nNote: this item comes from a feed \u2014 it returns on the next sync if the feed still lists it. Disable the feed to drop it permanently.';
  if (!confirm(msg)) return;
  const status = document.getElementById('items-status');
  try {
    const res = await authFetch('/api/lists/items/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ list: itemsState.listType, items: [value] })
    });
    const authErr = handleAuthError(res);
    if (authErr) { status.textContent = authErr; return; }
    const data = await res.json();
    if (data.status === 'ok') {
      status.textContent = '\u2705 Removed ' + data.removed;
      loadListItems();
    } else {
      status.textContent = '\u274C ' + (data.error || 'Failed to remove');
    }
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
  }
}
</script>
</body>
</html>`;
}
