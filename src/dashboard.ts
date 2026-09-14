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
            <td><input type="checkbox" ${enabled ? "checked" : ""} onchange="toggleFeed(this, '${f.id}')"/></td>
            <td><span class="badge badge-${f.listType}">${f.listType.toUpperCase()}</span></td>
            <td>${esc(f.name)}${f.custom ? '<span class="custom-tag">custom</span>' : ""}</td>
            <td>${f.listType === "url" ? "IOC-URLs" : "IOC-Domains"}</td>
            <td class="settings-actions">${f.custom ? `<button class="btn-remove" onclick="removeCustomFeed('${f.id}')">\u2715 Remove</button>` : ""}</td>
          </tr>`;
    })
    .join("\n");
}

export function renderDashboard(lastSync: SyncResult | null, cfg: FeedConfig = { disabled: [], custom: [] }): string {
  const ts = lastSync
    ? new Date(lastSync.ts).toLocaleString("en-GB", { timeZone: "Asia/Bangkok", hour12: false })
    : "Never";
  const elapsed = lastSync ? `${(lastSync.elapsedMs / 1e3).toFixed(1)}s` : "\u2014";
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
  function feedRows(feeds: [string, number][], type: string): string {
    if (!feeds.length) return '<tr><td colspan="3" class="empty">No data yet \u2014 run a sync</td></tr>';
    return feeds
      .map(
        ([id, count]) => `
      <tr>
        <td><span class="badge badge-${type}">${type.toUpperCase()}</span></td>
        <td>${esc(feedNames[id] ?? id)}</td>
        <td class="count">${count.toLocaleString()}</td>
      </tr>`,
      )
      .join("");
  }
  const errors = lastSync?.feedErrors ?? [];
  const errHtml = errors.length
    ? `<div class="errors"><div class="err-title">\u26A0 Feed Errors (${errors.length})</div>${errors
        .map((e) => `<div class="err-item">${esc(e)}</div>`)
        .join("")}</div>`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>TI IOC Sync \u2014 Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0a0e1a;
      color: #e2e8f0;
      min-height: 100vh;
      padding: 0 0 60px;
    }

    /* \u2500\u2500 Header \u2500\u2500 */
    .header {
      background: linear-gradient(135deg, #f6821f 0%, #ff4500 50%, #c0392b 100%);
      padding: 28px 40px 24px;
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .header-logo {
      width: 48px; height: 48px; border-radius: 10px;
      background: rgba(255,255,255,0.15);
      display: flex; align-items: center; justify-content: center;
      font-size: 28px;
    }
    .header-text h1 { font-size: 22px; font-weight: 700; color: #fff; }
    .header-text p  { font-size: 13px; color: rgba(255,255,255,0.8); margin-top: 2px; }

    .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px 0; }

    /* \u2500\u2500 Stat cards \u2500\u2500 */
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .stat-card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 20px 24px;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: "";
      position: absolute; top: 0; left: 0; right: 0; height: 3px;
    }
    .stat-card.orange::before { background: linear-gradient(90deg, #f6821f, #fbad41); }
    .stat-card.blue::before   { background: linear-gradient(90deg, #3b82f6, #06b6d4); }
    .stat-card.green::before  { background: linear-gradient(90deg, #10b981, #34d399); }
    .stat-card.purple::before { background: linear-gradient(90deg, #8b5cf6, #a78bfa); }
    .stat-card.red::before    { background: linear-gradient(90deg, #ef4444, #f97316); }
    .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; margin-bottom: 6px; }
    .stat-value { font-size: 32px; font-weight: 700; color: #f1f5f9; line-height: 1; }
    .stat-sub   { font-size: 12px; color: #6b7280; margin-top: 6px; }

    /* \u2500\u2500 Section \u2500\u2500 */
    .section { margin-bottom: 32px; }
    .section-title {
      font-size: 14px; font-weight: 600; text-transform: uppercase;
      letter-spacing: .08em; color: #9ca3af;
      margin-bottom: 14px; padding-bottom: 8px;
      border-bottom: 1px solid #1f2937;
    }

    /* \u2500\u2500 Logic flow \u2500\u2500 */
    .flow {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 24px;
    }
    .flow-row {
      display: flex; align-items: flex-start; gap: 0; flex-wrap: wrap;
    }
    .flow-step {
      flex: 1; min-width: 130px;
      display: flex; flex-direction: column; align-items: center;
      text-align: center; padding: 0 4px;
    }
    .flow-icon {
      width: 52px; height: 52px; border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 22px; margin-bottom: 8px;
    }
    .flow-icon.orange { background: rgba(246,130,31,.15); border: 1px solid rgba(246,130,31,.3); }
    .flow-icon.blue   { background: rgba(59,130,246,.15); border: 1px solid rgba(59,130,246,.3); }
    .flow-icon.purple { background: rgba(139,92,246,.15); border: 1px solid rgba(139,92,246,.3); }
    .flow-icon.green  { background: rgba(16,185,129,.15); border: 1px solid rgba(16,185,129,.3); }
    .flow-icon.red    { background: rgba(239,68,68,.15);  border: 1px solid rgba(239,68,68,.3); }
    .flow-icon.cyan   { background: rgba(6,182,212,.15);  border: 1px solid rgba(6,182,212,.3); }
    .flow-name { font-size: 12px; font-weight: 600; color: #e2e8f0; margin-bottom: 3px; }
    .flow-desc { font-size: 11px; color: #6b7280; line-height: 1.4; }
    .flow-arrow {
      align-self: center; color: #374151; font-size: 20px; padding: 0 2px;
      flex-shrink: 0;
    }

    /* \u2500\u2500 Tables \u2500\u2500 */
    .table-wrap {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; }
    th {
      background: #0f172a; text-align: left;
      padding: 10px 16px; font-size: 11px;
      text-transform: uppercase; letter-spacing: .06em; color: #6b7280;
    }
    td {
      padding: 10px 16px; font-size: 13px; color: #d1d5db;
      border-top: 1px solid #1f2937;
    }
    td.count { font-weight: 700; font-family: monospace; font-size: 14px; color: #f1f5f9; text-align: right; }
    td.empty { color: #6b7280; font-style: italic; text-align: center; padding: 20px; }
    tr:hover td { background: rgba(255,255,255,.02); }

    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: 10px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
    }
    .badge-url    { background: rgba(59,130,246,.2);  color: #60a5fa; border: 1px solid rgba(59,130,246,.3); }
    .badge-domain { background: rgba(16,185,129,.2);  color: #34d399; border: 1px solid rgba(16,185,129,.3); }

    /* \u2500\u2500 Two-col grid \u2500\u2500 */
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }

    .list-header {
      padding: 12px 16px 8px;
      display: flex; align-items: center; justify-content: space-between;
    }
    .list-header-title { font-size: 13px; font-weight: 600; color: #f1f5f9; }
    .list-count-pill {
      background: #1f2937; border-radius: 20px;
      padding: 2px 10px; font-size: 12px; font-weight: 700;
      font-family: monospace; color: #f1f5f9;
    }

    /* \u2500\u2500 Errors \u2500\u2500 */
    .errors {
      background: rgba(239,68,68,.08);
      border: 1px solid rgba(239,68,68,.25);
      border-radius: 10px; padding: 14px 16px; margin-bottom: 24px;
    }
    .err-title { font-size: 13px; font-weight: 600; color: #f87171; margin-bottom: 8px; }
    .err-item  { font-size: 12px; color: #fca5a5; font-family: monospace; padding: 2px 0; }

    /* \u2500\u2500 Sync button \u2500\u2500 */
    .actions { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
    .btn {
      padding: 10px 22px; border-radius: 8px; border: none;
      font-size: 13px; font-weight: 600; cursor: pointer;
      display: inline-flex; align-items: center; gap: 8px;
      transition: opacity .15s;
    }
    .btn:hover { opacity: .85; }
    .btn:disabled { opacity: .5; cursor: not-allowed; }
    .btn-primary  { background: linear-gradient(135deg,#f6821f,#ff4500); color: #fff; }
    .btn-secondary{ background: #1f2937; color: #e2e8f0; border: 1px solid #374151; }
    .btn-matrix   { background: #000; color: #00ff41; border: 1px solid #00ff41;
                    font-family: monospace; text-shadow: 0 0 6px #00ff41; }
    .btn-matrix:hover { background: #001a00; box-shadow: 0 0 12px #00ff4155; }
    #sync-status { font-size: 13px; color: #9ca3af; align-self: center; }

    /* \u2500\u2500 Matrix Terminal \u2500\u2500 */
    #matrix-wrap {
      display: none;
      margin-bottom: 32px;
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid #00ff4133;
      box-shadow: 0 0 40px #00ff4122, inset 0 0 80px #000a00;
    }
    .matrix-titlebar {
      background: #000;
      border-bottom: 1px solid #00ff4133;
      padding: 8px 16px;
      display: flex; align-items: center; justify-content: space-between;
    }
    .matrix-titlebar-left { display: flex; align-items: center; gap: 10px; }
    .matrix-dot { width: 12px; height: 12px; border-radius: 50%; }
    .matrix-dot.red    { background:#ff5f56; }
    .matrix-dot.yellow { background:#ffbd2e; }
    .matrix-dot.green  { background:#27c93f; }
    .matrix-title {
      font-family: monospace; font-size: 12px; color: #00ff41;
      text-shadow: 0 0 6px #00ff41;
    }
    .matrix-status {
      font-family: monospace; font-size: 11px; color: #00bb30;
      display: flex; align-items: center; gap: 6px;
    }
    .matrix-blink {
      display: inline-block; width: 8px; height: 8px; border-radius: 50%;
      background: #00ff41;
      animation: mblink 1s step-start infinite;
    }
    @keyframes mblink { 50% { opacity: 0; } }
    #matrix-term {
      background: #000;
      padding: 18px 22px;
      height: 420px;
      overflow-y: auto;
      font-family: "Courier New", "Lucida Console", monospace;
      font-size: 12.5px;
      line-height: 1.6;
      color: #00cc33;
      text-shadow: 0 0 4px #00cc3388;
      scroll-behavior: smooth;
    }
    /* scanline effect */
    #matrix-term::after {
      content: "";
      display: block;
      position: sticky;
      bottom: 0; left: 0; right: 0;
      height: 2px;
      background: rgba(0,255,65,.06);
      pointer-events: none;
    }
    .ml { display: block; white-space: pre-wrap; word-break: break-all; }
    .ml-dim    { color: #006618; }
    .ml-head   { color: #00ff41; font-weight: bold; text-shadow: 0 0 8px #00ff41; }
    .ml-step   { color: #39ff14; font-weight: bold; }
    .ml-feed   { color: #00cc33; }
    .ml-intel  { color: #00e5cc; text-shadow: 0 0 4px #00e5cc66; }
    .ml-add    { color: #00ff41; }
    .ml-remove { color: #ff6b35; text-shadow: 0 0 4px #ff6b3566; }
    .ml-done   { color: #00ff41; font-weight: bold; text-shadow: 0 0 10px #00ff41; }
    .ml-error  { color: #ff3333; text-shadow: 0 0 6px #ff333388; }
    .ml-cursor::after {
      content: "\u2588";
      animation: mblink 1s step-start infinite;
      color: #00ff41;
    }

    /* \u2500\u2500 Feed settings \u2500\u2500 */
    td input[type=checkbox] { width:16px; height:16px; accent-color:#f6821f; cursor:pointer; }
    .custom-tag {
      font-size:9px; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
      background:rgba(139,92,246,.2); color:#a78bfa; border:1px solid rgba(139,92,246,.35);
      border-radius:4px; padding:1px 6px; margin-left:8px; vertical-align:middle;
    }
    .btn-remove {
      background:rgba(239,68,68,.12); color:#f87171; border:1px solid rgba(239,68,68,.35);
      border-radius:6px; padding:4px 10px; font-size:11px; cursor:pointer;
    }
    .btn-remove:hover { background:rgba(239,68,68,.25); }
    td.settings-actions { text-align: right; }
    .custom-add {
      display:flex; gap:10px; align-items:center; flex-wrap:wrap;
      padding:14px 16px; border-top:1px solid #1f2937;
    }
    .custom-add input[type=text] {
      flex:1; min-width:260px; background:#0a0e1a; border:1px solid #374151; border-radius:8px;
      color:#e2e8f0; padding:10px 12px; font-size:13px; font-family:monospace;
    }
    .custom-add input[type=text]:focus { outline:none; border-color:#f6821f; }
    .custom-add select {
      background:#0a0e1a; border:1px solid #374151; border-radius:8px;
      color:#e2e8f0; padding:10px 12px; font-size:13px;
    }
    #feed-status { font-size:12px; color:#9ca3af; }
    .feed-hint { width:100%; font-size:11px; color:#6b7280; }
    #item-search { max-width:180px; }

    /* \u2500\u2500 List items manager \u2500\u2500 */
    .tabs { display:flex; gap:8px; }
    .tab {
      padding:6px 16px; border-radius:8px; border:1px solid #374151;
      background:#0a0e1a; color:#9ca3af; font-size:12px; font-weight:600; cursor:pointer;
      transition: opacity .15s;
    }
    .tab:hover { opacity:.85; }
    .tab.active { background:linear-gradient(135deg,#f6821f,#ff4500); color:#fff; border-color:transparent; }
    .item-value { font-family:monospace; font-size:12px; word-break:break-all; }
    .badge-manual {
      display:inline-block; padding:1px 6px; margin-left:8px; border-radius:4px;
      font-size:9px; font-weight:700; letter-spacing:.05em; text-transform:uppercase;
      background:rgba(139,92,246,.2); color:#a78bfa; border:1px solid rgba(139,92,246,.35);
      vertical-align:middle;
    }
    .btn-icon {
      background:rgba(239,68,68,.12); color:#f87171; border:1px solid rgba(239,68,68,.35);
      border-radius:6px; padding:3px 9px; font-size:11px; cursor:pointer;
    }
    .btn-icon:hover { background:rgba(239,68,68,.25); }
    .items-pager {
      display:flex; align-items:center; gap:12px; justify-content:center;
      padding:10px; border-top:1px solid #1f2937; font-size:12px; color:#9ca3af;
    }
    .items-pager button {
      background:#1f2937; color:#e2e8f0; border:1px solid #374151;
      border-radius:6px; padding:4px 12px; cursor:pointer; font-size:12px;
    }
    .items-pager button:disabled { opacity:.4; cursor:not-allowed; }

    /* \u2500\u2500 Footer \u2500\u2500 */
    .footer {
      text-align: center; margin-top: 48px;
      font-size: 12px; color: #374151;
    }
    .footer a { color: #f6821f; text-decoration: none; }

    /* \u2500\u2500 Pulse dot \u2500\u2500 */
    .pulse { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981; margin-right: 6px; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(1.3)} }
  </style>
</head>
<body>

<div class="header">
  <div class="header-logo">\u{1F6E1}</div>
  <div class="header-text">
    <h1>Threat Intelligence IOC Sync</h1>
    <p><span class="pulse"></span>Live feed sync to Cloudflare Gateway Lists \u2014 auto-sync daily at 08:00 UTC</p>
  </div>
</div>

<div class="container">

  <!-- Stats row -->
  <div class="stats">
    <div class="stat-card orange">
      <div class="stat-label">Domain IOCs</div>
      <div class="stat-value">${(lastSync?.domains.total ?? 0).toLocaleString()}</div>
      <div class="stat-sub">IOC-Domains Gateway List</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">URL IOCs</div>
      <div class="stat-value">${(lastSync?.urls.total ?? 0).toLocaleString()}</div>
      <div class="stat-sub">IOC-URLs Gateway List</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Intel Skipped</div>
      <div class="stat-value">${(lastSync?.domains.intelSkipped ?? 0).toLocaleString()}</div>
      <div class="stat-sub">Already covered by CF policy</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">Last Sync</div>
      <div class="stat-value" style="font-size:18px;padding-top:4px">${ts}</div>
      <div class="stat-sub">Elapsed: ${elapsed}</div>
    </div>
    <div class="stat-card ${errors.length ? "red" : "green"}">
      <div class="stat-label">Feed Errors</div>
      <div class="stat-value">${errors.length}</div>
      <div class="stat-sub">${errors.length ? "See details below" : "All feeds healthy"}</div>
    </div>
  </div>

  <!-- Actions -->
  <div class="actions">
    <button class="btn btn-primary" id="sync-btn" onclick="triggerSync()">\u26A1 Run Sync Now</button>
    <button class="btn btn-matrix" id="stream-btn" onclick="toggleStream()">&#9654; Live Sync Terminal</button>
    <button class="btn btn-secondary" onclick="location.reload()">\u21BB Refresh</button>
    <span id="sync-status"></span>
  </div>

  <!-- Matrix Terminal -->
  <div id="matrix-wrap">
    <div class="matrix-titlebar">
      <div class="matrix-titlebar-left">
        <span class="matrix-dot red"></span>
        <span class="matrix-dot yellow"></span>
        <span class="matrix-dot green"></span>
        <span class="matrix-title">ti-ioc-sync \u2014 live stream &nbsp;/sync/stream</span>
      </div>
      <div class="matrix-status">
        <span class="matrix-blink" id="stream-blink" style="display:none"></span>
        <span id="stream-label">READY</span>
      </div>
    </div>
    <div id="matrix-term"><span class="ml ml-dim">-- press &#9654; Live Sync Terminal to start --</span></div>
  </div>

  ${errHtml}

  <!-- Logic flow -->
  <div class="section">
    <div class="section-title">How It Works \u2014 Sync Logic</div>
    <div class="flow">
      <div class="flow-row">
        <div class="flow-step">
          <div class="flow-icon orange">\u{1F310}</div>
          <div class="flow-name">OSINT Feeds</div>
          <div class="flow-desc">Feeds fetched daily at 08:00 UTC via cron</div>
        </div>
        <div class="flow-arrow">\u203A</div>
        <div class="flow-step">
          <div class="flow-icon blue">\u{1F500}</div>
          <div class="flow-name">Parse &amp; Split</div>
          <div class="flow-desc">URL feeds \u2192 full URLs<br>Domain feeds \u2192 hostnames</div>
        </div>
        <div class="flow-arrow">\u203A</div>
        <div class="flow-step">
          <div class="flow-icon purple">\u{1F9F9}</div>
          <div class="flow-name">Deduplicate</div>
          <div class="flow-desc">Dedup + whitelist + 5,000 item cap per list</div>
        </div>
        <div class="flow-arrow">\u203A</div>
        <div class="flow-step">
          <div class="flow-icon cyan">\u{1F50D}</div>
          <div class="flow-name">CF Intel Check</div>
          <div class="flow-desc">Domains only \u2014 skip if CF already categorises as threat</div>
        </div>
        <div class="flow-arrow">\u203A</div>
        <div class="flow-step">
          <div class="flow-icon green">\u{1F4CB}</div>
          <div class="flow-name">Diff</div>
          <div class="flow-desc">Compare vs current Gateway List \u2014 compute add/remove</div>
        </div>
        <div class="flow-arrow">\u203A</div>
        <div class="flow-step">
          <div class="flow-icon orange">\u2705</div>
          <div class="flow-name">Sync to CF</div>
          <div class="flow-desc">PATCH Gateway List \u2014 remove stale, append new</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Feed tables -->
  <div class="two-col">
    <div class="section">
      <div class="section-title">URL Feeds \u2192 IOC-URLs</div>
      <div class="table-wrap">
        <div class="list-header">
          <span class="list-header-title">Full URL blocking (path-aware)</span>
          <span class="list-count-pill">${(lastSync?.urls.total ?? 0).toLocaleString()} URLs</span>
        </div>
        <table>
          <thead><tr><th>Type</th><th>Feed</th><th style="text-align:right">Items</th></tr></thead>
          <tbody>${feedRows(urlFeeds, "url")}</tbody>
        </table>
        <div style="padding:8px 16px;font-size:11px;color:#6b7280;border-top:1px solid #1f2937">
          +${lastSync?.urls.added ?? 0} added &nbsp;\xB7&nbsp; -${lastSync?.urls.removed ?? 0} removed this cycle
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Domain Feeds \u2192 IOC-Domains</div>
      <div class="table-wrap">
        <div class="list-header">
          <span class="list-header-title">Hostname blocking (DNS + HTTP)</span>
          <span class="list-count-pill">${(lastSync?.domains.total ?? 0).toLocaleString()} domains</span>
        </div>
        <table>
          <thead><tr><th>Type</th><th>Feed</th><th style="text-align:right">Items</th></tr></thead>
          <tbody>${feedRows(domainFeeds, "domain")}</tbody>
        </table>
        <div style="padding:8px 16px;font-size:11px;color:#6b7280;border-top:1px solid #1f2937">
          +${lastSync?.domains.added ?? 0} added &nbsp;\xB7&nbsp; -${lastSync?.domains.removed ?? 0} removed &nbsp;\xB7&nbsp; ${lastSync?.domains.intelSkipped ?? 0} skipped (CF Intel)
        </div>
      </div>
    </div>
  </div>

  <!-- Feed settings -->
  <div class="section">
    <div class="section-title">Feed Settings \u2014 Enable / Disable / Custom Feeds</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Enabled</th><th>Type</th><th>Feed</th><th>List</th><th></th></tr></thead>
        <tbody>
${feedSettingsRows(cfg)}
        </tbody>
      </table>
      <div class="custom-add">
        <input type="text" id="custom-url" placeholder="https://example.com/blocklist.txt" spellcheck="false"/>
        <select id="custom-type">
          <option value="domain">Domain list</option>
          <option value="url">URL list</option>
        </select>
        <button class="btn btn-primary" onclick="addCustomFeed()">+ Add Feed</button>
        <span id="feed-status"></span>
        <div class="feed-hint">Only <b>.txt</b> plain-text lists are accepted \u2014 one domain or URL per line, # comments allowed. Custom feeds are capped at 500 items each (max 10 feeds). IP-literal, localhost, and credential-bearing URLs are rejected. Admin actions require the <b>ADMIN_TOKEN</b> secret (prompted once per tab session).</div>
      </div>
    </div>
  </div>

  <!-- List items manager -->
  <div class="section">
    <div class="section-title">Gateway List Items \u2014 Manual Add / Remove</div>
    <div class="table-wrap">
      <div class="list-header">
        <div class="tabs">
          <button id="tab-domain" class="tab active" onclick="switchListTab('domain')">IOC-Domains</button>
          <button id="tab-url" class="tab" onclick="switchListTab('url')">IOC-URLs</button>
        </div>
        <span class="list-count-pill" id="items-count">\u2014</span>
      </div>
      <div class="custom-add">
        <input type="text" id="item-input" placeholder="example.com (comma/newline separated for multiple)" spellcheck="false"/>
        <button class="btn btn-primary" onclick="addListItems()">+ Add</button>
        <input type="text" id="item-search" placeholder="Search\u2026" oninput="renderItemsTable()" spellcheck="false"/>
        <button class="btn btn-secondary" onclick="loadListItems()">\u21BB Load / Refresh</button>
        <span id="items-status"></span>
        <div class="feed-hint">Manually added items are stored in KV and survive syncs (they are merged ahead of feed content). Items that come from a feed always return on the next sync if the feed still lists them \u2014 disable the feed to drop them permanently. Whitelisted domains are rejected. The 5,000-item cap applies.</div>
      </div>
      <table>
        <thead><tr><th>Value</th><th style="text-align:right;width:100px"></th></tr></thead>
        <tbody id="items-tbody"><tr><td colspan="2" class="empty">Press \u21BB Load / Refresh to view items (requires the admin token)</td></tr></tbody>
      </table>
      <div class="items-pager">
        <button id="items-prev" onclick="itemsPage(-1)" disabled>\u2039 Prev</button>
        <span id="items-page-info">\u2013</span>
        <button id="items-next" onclick="itemsPage(1)" disabled>Next \u203A</button>
      </div>
    </div>
  </div>

  <!-- Intel explanation -->
  <div class="section">
    <div class="section-title">Cloudflare Intel Deduplication</div>
    <div class="flow" style="padding:20px 24px">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px">
        <div style="text-align:center;padding:16px;background:#0f172a;border-radius:10px;border:1px solid #1f2937">
          <div style="font-size:28px;margin-bottom:8px">\u{1F50E}</div>
          <div style="font-size:13px;font-weight:600;color:#f1f5f9;margin-bottom:4px">CF Intel API</div>
          <div style="font-size:12px;color:#6b7280">Checks each new domain against Cloudflare's threat intelligence database</div>
        </div>
        <div style="text-align:center;padding:16px;background:#0f172a;border-radius:10px;border:1px solid rgba(239,68,68,.3)">
          <div style="font-size:28px;margin-bottom:8px">\u{1F6AB}</div>
          <div style="font-size:13px;font-weight:600;color:#f87171;margin-bottom:4px">Skip if already known</div>
          <div style="font-size:12px;color:#6b7280">Malware \xB7 Phishing \xB7 C2 &amp; Botnet \xB7 Cryptomining \xB7 DGA \xB7 Spyware \xB7 Scam \xB7 Anonymizer</div>
        </div>
        <div style="text-align:center;padding:16px;background:#0f172a;border-radius:10px;border:1px solid rgba(16,185,129,.3)">
          <div style="font-size:28px;margin-bottom:8px">\u2705</div>
          <div style="font-size:13px;font-weight:600;color:#34d399;margin-bottom:4px">Add only new threats</div>
          <div style="font-size:12px;color:#6b7280">Avoids filling the 5,000 item limit with domains Gateway already blocks via built-in categories</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Gateway policy usage -->
  <div class="section">
    <div class="section-title">Gateway Policy Usage</div>
    <div class="table-wrap" style="padding:20px 24px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div style="background:#0f172a;border-radius:10px;padding:16px;border:1px solid #1f2937">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;margin-bottom:10px">DNS Policy</div>
          <code style="font-size:12px;color:#34d399;background:#0a0e1a;padding:10px 12px;border-radius:6px;display:block;line-height:1.7">dns.fqdn in $IOC-Domains</code>
          <div style="font-size:12px;color:#6b7280;margin-top:10px">Blocks DNS resolution of malicious hostnames before any connection is made</div>
        </div>
        <div style="background:#0f172a;border-radius:10px;padding:16px;border:1px solid #1f2937">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;margin-bottom:10px">HTTP Policy</div>
          <code style="font-size:12px;color:#60a5fa;background:#0a0e1a;padding:10px 12px;border-radius:6px;display:block;line-height:1.7">http.request.full_uri in $IOC-URLs<br>OR http.request.domains[*] in $IOC-Domains</code>
          <div style="font-size:12px;color:#6b7280;margin-top:10px">Blocks specific malicious URLs (path-aware) and any request to known malicious domains</div>
        </div>
      </div>
    </div>
  </div>

</div><!-- /container -->

<div class="footer">
  Powered by <a href="https://developers.cloudflare.com/cloudflare-one/policies/gateway/" target="_blank">Cloudflare Gateway</a> &nbsp;\xB7&nbsp;
  <a href="/api/status" target="_blank">JSON API</a> &nbsp;\xB7&nbsp;
  Auto-syncs daily at 08:00 UTC &nbsp;\xB7&nbsp;
  <a href="https://github.com/pongpisit/cloudflare-ti-ioc-sync" target="_blank">github.com/pongpisit/cloudflare-ti-ioc-sync</a>
</div>

<script>
// \u2500\u2500 Admin token \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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

// \u2500\u2500 Sync button \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async function triggerSync() {
  const btn = document.getElementById('sync-btn');
  const status = document.getElementById('sync-status');
  btn.disabled = true;
  btn.textContent = '\u23F3 Syncing\u2026';
  status.textContent = '';
  try {
    // Inline request: the sync runs within the request lifetime. (Background
    // waitUntil tasks are cancelled ~30s after the response, so POST /sync
    // cannot carry a full sync.) If the edge proxy ever times the request
    // out, the Live Sync Terminal still streams every step.
    const res = await authFetch('/sync/run', { method: 'POST' });
    const authErr = handleAuthError(res);
    if (authErr) { status.textContent = authErr; return; }
    if (!res.ok) {
      const data = await res.json().catch(function(){ return {}; });
      status.textContent = '\u274C ' + (data.error || 'HTTP ' + res.status + ' \u2014 try the Live Sync Terminal instead');
      return;
    }
    const data = await res.json();
    if (data.status === 'ok') {
      const r = data.result;
      status.textContent = '\u2705 Done \u2014 domains +' + r.domains.added + '/-' + r.domains.removed + '=' + r.domains.total +
                          '  urls +' + r.urls.added + '/-' + r.urls.removed + '=' + r.urls.total;
      setTimeout(function(){ location.reload(); }, 2500);
    } else {
      status.textContent = '\u274C ' + (data.error || 'Unknown error');
    }
  } catch(e) {
    status.textContent = e.message === 'admin token required' ? '\u26BF Admin token required' : '\u274C Network error';
  }
  btn.disabled = false;
  btn.textContent = '\u26A1 Run Sync Now';
}

// \u2500\u2500 Matrix Terminal \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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
  const wrap  = document.getElementById('matrix-wrap');
  const term  = document.getElementById('matrix-term');
  const btn   = document.getElementById('stream-btn');
  const blink = document.getElementById('stream-blink');
  const label = document.getElementById('stream-label');
  const t = getAdminToken();
  if (t === null) {
    label.textContent = 'TOKEN REQUIRED';
    return;
  }

  wrap.style.display = 'block';
  term.innerHTML = '';
  btn.textContent = '\u23F9 Stop Terminal';
  blink.style.display = 'inline-block';
  label.textContent = 'STREAMING';
  streamOpen = true;

  // Scroll terminal into view
  wrap.scrollIntoView({ behavior: 'smooth', block: 'start' });

  streamController = new AbortController();

  fetch('/sync/stream', { signal: streamController.signal, headers: { 'X-Auth-Token': t } })
    .then(res => {
      if (res.status === 401 || res.status === 503) {
        sessionStorage.removeItem('ti_admin_token');
        appendLine(term, '[ERROR] Unauthorized \u2014 check the ADMIN_TOKEN secret');
        label.textContent = 'UNAUTHORIZED';
        blink.style.display = 'none';
        btn.textContent = '&#9654; Live Sync Terminal';
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
            btn.textContent = '&#9654; Live Sync Terminal';
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
      btn.textContent = '&#9654; Live Sync Terminal';
      streamOpen = false;
    });
}

function stopStream() {
  if (streamController) streamController.abort();
  const btn   = document.getElementById('stream-btn');
  const blink = document.getElementById('stream-blink');
  const label = document.getElementById('stream-label');
  btn.textContent = '&#9654; Live Sync Terminal';
  blink.style.display = 'none';
  label.textContent = 'STOPPED';
  streamOpen = false;
}

function appendLine(term, raw) {
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

// \u2500\u2500 Feed settings \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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
// \u2500\u2500 List items manager \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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
      tdA.style.textAlign = 'right';
      const btn = document.createElement('button');
      btn.className = 'btn-icon';
      btn.textContent = '\u2715 Remove';
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
    : 'Remove ' + value + ' from the list?\\n\\nNote: this item comes from a feed \\u2014 it returns on the next sync if the feed still lists it. Disable the feed to drop it permanently.';
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
