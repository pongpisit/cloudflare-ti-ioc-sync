#!/usr/bin/env node
// Bulk-import a plain-text or CSV file into a Gateway list through the
// ti-ioc-sync Worker's manual-items API. Items are registered as "manual"
// so the daily feed sync never removes them.
//
// Usage:
//   node scripts/upload-list.mjs <add|remove> <domain|url> <file> [host]
//
// Examples:
//   node scripts/upload-list.mjs add domain my-hostnames.txt
//   node scripts/upload-list.mjs add url my-urls.txt https://ti-ioc-sync.pongpisit.workers.dev
//   node scripts/upload-list.mjs remove domain cleanup.txt
//
// File format (either works):
//   - Plain text: one value per line; blank lines and #-comment lines ignored
//   - CSV exported for the Zero Trust dashboard: a `value,description` header row
//     is skipped automatically; only the first column is imported
//
// The ADMIN_TOKEN is read from $ADMIN_TOKEN, or from .dev.vars in the repo root.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BATCH_SIZE = 500; // API accepts up to 1,000 per request; stay comfortable

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function usage() {
  fail("usage: node scripts/upload-list.mjs <add|remove> <domain|url> <file> [host]");
}

function readAdminToken() {
  if (process.env.ADMIN_TOKEN) return process.env.ADMIN_TOKEN;
  try {
    const vars = readFileSync(join(repoRoot, ".dev.vars"), "utf8");
    const m = vars.match(/^ADMIN_TOKEN=(.+)$/m);
    if (m) return m[1].trim();
  } catch {
    // no .dev.vars — fall through to the error below
  }
  fail("ADMIN_TOKEN not found — set $ADMIN_TOKEN or create .dev.vars (see .dev.vars.example)");
}

function parseFile(path, listType) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    fail(`cannot read ${path}: ${err.message}`);
  }
  const values = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.replace(/^\uFEFF/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    // CSV support: take the first column, skip the `value[,description]` header
    const first = line.split(",")[0].trim();
    if (/^value$/i.test(first)) continue;
    values.push(listType === "domain" ? first : line);
  }
  return [...new Set(values)];
}

async function post(host, path, token, body) {
  const res = await fetch(`${host}${path}`, {
    method: "POST",
    headers: { "X-Auth-Token": token, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status === 401 || res.status === 403 || res.status === 503) {
    fail(`auth rejected (HTTP ${res.status}) — check ADMIN_TOKEN for this Worker`);
  }
  const json = await res.json();
  if (json.status !== "ok") {
    fail(`API error: ${JSON.stringify(json).slice(0, 300)}`);
  }
  return json;
}

async function main() {
  const [action, listType, file, host = "https://ti-ioc-sync.pongpisit.workers.dev"] = process.argv.slice(2);
  if (!["add", "remove"].includes(action)) usage();
  if (!["domain", "url"].includes(listType)) usage();
  if (!file) usage();

  const token = readAdminToken();
  const values = parseFile(file, listType);
  if (values.length === 0) fail(`no importable values found in ${file}`);
  console.log(`${action === "add" ? "importing" : "removing"} ${values.length} unique value(s) ${action === "add" ? "into" : "from"} the ${listType} list via ${host}`);

  let done = 0;
  const skipped = [];
  for (let i = 0; i < values.length; i += BATCH_SIZE) {
    const batch = values.slice(i, i + BATCH_SIZE);
    const path = action === "add" ? "/api/lists/items" : "/api/lists/items/remove";
    const json = await post(host, path, token, { list: listType, items: batch });
    done += action === "add" ? json.added ?? 0 : json.removed ?? 0;
    skipped.push(...(json.skipped ?? []));
    console.log(
      `  batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(values.length / BATCH_SIZE)}: ` +
        `${action === "add" ? `+${json.added ?? 0} added` : `-${json.removed ?? 0} removed`}` +
        (json.skipped?.length ? `, ${json.skipped.length} skipped` : ""),
    );
  }

  console.log(`done: ${done} ${action === "add" ? "imported (registered as manual — they survive syncs)" : "removed"}`);
  if (skipped.length > 0) {
    console.log(`skipped ${skipped.length}:`);
    for (const s of skipped.slice(0, 10)) console.log(`  ${s.value} (${s.reason})`);
    if (skipped.length > 10) console.log(`  … and ${skipped.length - 10} more`);
  }
}

main().catch((err) => fail(err.message));
