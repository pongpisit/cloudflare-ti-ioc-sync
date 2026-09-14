import { isValidDomain, parseFeed, parseUrls } from "./feeds";
import {
  appendToList,
  appendToUrlList,
  clearUrlList,
  createList,
  debugListItems,
  deleteFromList,
  deleteFromUrlList,
  fetchListValues,
  getListItems,
  getUrlListItems,
} from "./cfapi";
import { filterCfKnownThreats } from "./intel";
import { renderDashboard } from "./dashboard";
import { loadManualItems, saveManualItems, type ManualItems } from "./listitems";
import { WHITELIST, isWhitelistedUrl } from "./whitelist";
import {
  addCustomFeed,
  getActiveFeeds,
  getFeedsWithState,
  loadFeedConfig,
  removeCustomFeed,
  toggleFeed,
} from "./feedconfig";
import type { Env, Feed, FetchFeedResult, FeedListType, SyncLogger, SyncResult } from "./types";

const CF_LIST_MAX = 5_000;
// Feed bodies must survive between syncs so the stale-cache fallback can fire
// when a feed fails; 48 h comfortably covers the 24 h cron cadence.
const FEED_CACHE_TTL = 172_800;
// Upper bound on a feed response body before it is parsed or cached.
const MAX_FEED_BYTES = 8 * 1024 * 1024;
const USER_AGENT =
  "Mozilla/5.0 (compatible; CF-TI-Sync/1.0; +https://github.com/pongpisit/cloudflare-ti-ioc-sync)";

// Exact-match whitelist of high-trust domains excluded from the domain list, applied
// to feed content and manual list management alike (see src/whitelist.ts).

/**
 * Constant-time string comparison for shared-secret checks. The length check leaks
 * only the token length, which is standard practice for bearer secrets.
 */
function timingSafeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  if (ea.byteLength !== eb.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < ea.byteLength; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

/** Routes that stay readable without a token: the dashboard and its JSON status. */
function isPublicRoute(method: string, pathname: string): boolean {
  return method === "GET" && (pathname === "/" || pathname === "/api/status");
}

function unauthorized(): Response {
  return Response.json(
    { status: "error", error: "unauthorized \u2014 X-Auth-Token header required" },
    { status: 401, headers: { "WWW-Authenticate": "Bearer" } },
  );
}

function capItems(feed: Feed, items: string[]): string[] {
  return feed.maxDomains ? items.slice(0, feed.maxDomains) : items;
}

/** Reads a response body up to maxBytes, failing the fetch if the limit is exceeded. */
async function readBodyCapped(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body!.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`feed response exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

async function fetchFeed(feed: Feed, cacheKV: KVNamespace): Promise<FetchFeedResult> {
  const cacheKey = `feed:${feed.id}`;
  try {
    let rawText = "";
    let rawJson: unknown = null;
    if (feed.format === "json_threatfox") {
      const res = await fetch(feed.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT },
        body: JSON.stringify({ query: "get_iocs", days: 7 }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      rawJson = await readBodyCapped(res, MAX_FEED_BYTES).then((t) => JSON.parse(t));
    } else {
      const res = await fetch(feed.url, {
        headers: { "User-Agent": USER_AGENT },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      rawText = await readBodyCapped(res, MAX_FEED_BYTES);
    }
    const toCache = rawJson ? JSON.stringify(rawJson) : rawText;
    await cacheKV.put(cacheKey, toCache, { expirationTtl: FEED_CACHE_TTL });
    return { feedId: feed.id, items: capItems(feed, parseFeed(feed, rawText, rawJson)), listType: feed.listType };
  } catch (err) {
    const cached = await cacheKV.get(cacheKey);
    if (cached) {
      try {
        const rawJson = feed.format === "json_threatfox" ? JSON.parse(cached) : null;
        const items = capItems(feed, parseFeed(feed, cached, rawJson));
        return { feedId: feed.id, items, listType: feed.listType, error: `stale cache (fetch error: ${err})` };
      } catch {
        // stale cache unparseable — fall through to hard failure
      }
    }
    return { feedId: feed.id, items: [], listType: feed.listType, error: String(err) };
  }
}

function clock(): string {
  return new Date().toISOString().slice(11, 23);
}

function tryDecode(u: string): string {
  try {
    return decodeURIComponent(u);
  } catch {
    return u;
  }
}

const LINE = "\u2550".repeat(60);

/**
 * Core sync pipeline. When `log` is provided (live /sync/stream terminal), progress
 * is streamed line-by-line; the cron/manual paths run silently and store `last_sync`.
 *
 * Removals are fail-closed: items are only removed from the Gateway lists when every
 * active feed returned content this run, at least one feed is active, and neither bucket
 * was truncated by the list cap. A feed outage, an empty response, or a disabled feed
 * must never unblock previously-synced IOCs.
 */
export async function runSync(env: Env, log?: SyncLogger): Promise<SyncResult> {
  const startMs = Date.now();
  const write = log ?? (() => {});
  const feedErrors: string[] = [];
  const feedStats: Record<string, number> = {};
  const feeds = await getActiveFeeds(env);

  if (log) {
    write(`[${clock()}] ${LINE}`);
    write(`[${clock()}]  Cloudflare TI IOC Sync \u2014 live progress log`);
    write(`[${clock()}] ${LINE}`);
    write(`[${clock()}]`);
    write(`[${clock()}] STEP 1 \u2014 Fetching ${feeds.length} OSINT feeds in parallel`);
    write(`[${clock()}]`);
  }

  const results = await Promise.all(
    feeds.map(async (feed) => {
      write(`[${clock()}]   \u2197 ${feed.id}  ${feed.url}`);
      const start = Date.now();
      const result = await fetchFeed(feed, env.IOC_CACHE);
      const ms = Date.now() - start;
      if (log) {
        if (result.error) {
          write(`[${clock()}]   \u2717 ${feed.id}  ERROR: ${result.error}`);
        } else {
          write(
            `[${clock()}]   \u2713 ${feed.id}  [${feed.listType.toUpperCase()}]  ${result.items.length.toLocaleString()} items  (${ms}ms)`,
          );
          for (const item of result.items) write(`[${clock()}]     \u00B7 ${item}`);
        }
        write(`[${clock()}]`);
      }
      return result;
    }),
  );

  // Partition into domain / URL buckets
  const freshDomains: string[] = [];
  const freshUrls: string[] = [];
  let whitelistHits = 0;
  // Any active feed that yielded zero items (hard fetch failure with no usable stale
  // cache, or an empty/comment-only 200 body) disqualifies removals this run.
  let emptyFeeds = 0;
  for (const { feedId, items, listType, error } of results) {
    feedStats[feedId] = items.length;
    if (error) feedErrors.push(`${feedId}: ${error}`);
    if (items.length === 0) {
      emptyFeeds++;
      continue;
    }
    if (listType === "url") {
      for (const u of items) {
        if (isWhitelistedUrl(u)) {
          whitelistHits++;
          continue;
        }
        freshUrls.push(u);
      }
    } else {
      for (const d of items) {
        if (WHITELIST.has(d)) {
          whitelistHits++;
          continue;
        }
        freshDomains.push(d);
      }
    }
  }
  // Manually added items survive syncs: they are merged into the fresh sets ahead of
  // feed content, so neither the 5,000-item cap nor the removal diff can drop them.
  const manual = await loadManualItems(env);
  const manualDomainSet = new Set(manual.domain);
  const domainUnion = [...manual.domain];
  for (const d of freshDomains) if (!manualDomainSet.has(d)) domainUnion.push(d);
  const manualUrlSet = new Set(manual.url);
  const urlUnion = [...manual.url];
  for (const u of freshUrls) if (!manualUrlSet.has(u)) urlUnion.push(u);

  const freshDomainSet = new Set(freshDomains.slice(0, CF_LIST_MAX * 2));
  const freshDomainCapped = [...new Set(domainUnion)].slice(0, CF_LIST_MAX);
  const freshUrlSet = new Set(freshUrls.slice(0, CF_LIST_MAX * 2));
  const freshUrlCapped = [...new Set(urlUnion)].slice(0, CF_LIST_MAX);
  const domainCapTruncated = new Set(domainUnion).size > freshDomainCapped.length;
  const urlCapTruncated = new Set(urlUnion).size > freshUrlCapped.length;

  if (log) {
    write(`[${clock()}] STEP 2 \u2014 Partitioning into domain / URL buckets`);
    write(
      `[${clock()}]   Domain bucket : ${freshDomains.length.toLocaleString()} raw \u2192 ${freshDomainSet.size.toLocaleString()} unique \u2192 capped at ${freshDomainCapped.length.toLocaleString()}`,
    );
    write(
      `[${clock()}]   URL bucket    : ${freshUrls.length.toLocaleString()} raw \u2192 ${freshUrlSet.size.toLocaleString()} unique \u2192 capped at ${freshUrlCapped.length.toLocaleString()}`,
    );
    write(`[${clock()}]   Whitelist hits: ${whitelistHits}`);
    write(`[${clock()}]`);
    write(`[${clock()}] STEP 3 \u2014 Reading current Gateway List contents from Cloudflare`);
  }

  const [currentDomainSet, currentUrlSet] = await Promise.all([getListItems(env), getUrlListItems(env)]);

  if (log) {
    write(`[${clock()}]   IOC-Domains: ${currentDomainSet.size.toLocaleString()} items currently`);
    write(`[${clock()}]   IOC-URLs   : ${currentUrlSet.size.toLocaleString()} items currently`);
    write(`[${clock()}]`);
    write(`[${clock()}] STEP 4 \u2014 Computing diff (new vs stale)`);
  }

  // Fail-closed removal authorization: a feed outage, an empty feed response, a fully
  // disabled feed set, or cap truncation must never turn into unblocking.
  const removalsAuthorized =
    feeds.length > 0 && emptyFeeds === 0 && !domainCapTruncated && !urlCapTruncated;
  if (!removalsAuthorized) {
    const reasons: string[] = [];
    if (feeds.length === 0) reasons.push("no active feeds");
    if (emptyFeeds > 0) reasons.push(`${emptyFeeds} feed(s) returned no items`);
    if (domainCapTruncated) reasons.push("domain bucket exceeded list cap");
    if (urlCapTruncated) reasons.push("URL bucket exceeded list cap");
    const msg = `removals skipped (fail-closed): ${reasons.join(", ")}`;
    feedErrors.push(msg);
    write(`[${clock()}]   \u26A0 ${msg}`);
  }

  // Diff — URLs are compared after percent-decoding so encoded duplicates are caught
  const freshDomainSetCapped = new Set(freshDomainCapped);
  const rawDomainsToAdd = freshDomainCapped.filter((d) => !currentDomainSet.has(d));
  const domainsToRemove = removalsAuthorized
    ? [...currentDomainSet].filter((d) => !freshDomainSetCapped.has(d))
    : [];
  const freshUrlNorm = new Set(freshUrlCapped.map(tryDecode));
  const currentUrlNorm = new Map([...currentUrlSet].map((u) => [tryDecode(u), u]));
  const urlsToAdd = freshUrlCapped.filter((u) => !currentUrlNorm.has(tryDecode(u)));
  const urlsToRemove = removalsAuthorized
    ? [...currentUrlSet].filter((u) => !freshUrlNorm.has(tryDecode(u)))
    : [];

  if (log) {
    write(`[${clock()}]   Domains \u2014 to add: ${rawDomainsToAdd.length.toLocaleString()}  to remove: ${domainsToRemove.length.toLocaleString()}`);
    write(`[${clock()}]   URLs    \u2014 to add: ${urlsToAdd.length.toLocaleString()}  to remove: ${urlsToRemove.length.toLocaleString()}`);
    write(`[${clock()}]`);
    write(`[${clock()}] STEP 5 \u2014 Cloudflare Intel check (domains only, ${rawDomainsToAdd.length} candidates)`);
  }

  const { kept: domainsToAdd, skipped: intelSkipped, errors: intelErrors } = await filterCfKnownThreats(
    env,
    rawDomainsToAdd,
    {
      onChunk: (msg) => write(`[${clock()}]   ${msg}`),
      onSkipped: (details) => {
        for (const d of details) write(`[${clock()}]     \u2298 ${d.domain}  (risk_type_ids: ${d.riskTypeIds})`);
      },
    },
  );
  if (intelErrors.length) feedErrors.push(...intelErrors.map((e) => `intel: ${e}`));

  if (log) {
    write(
      `[${clock()}]   Intel summary: ${domainsToAdd.length} kept, ${intelSkipped.length} skipped, ${intelErrors.length} errors`,
    );
    write(`[${clock()}]`);
    write(`[${clock()}] STEP 6 \u2014 Applying changes to Cloudflare Gateway Lists`);
    write(`[${clock()}]`);
  }

  write(`[${clock()}]   [IOC-Domains]  removing ${domainsToRemove.length.toLocaleString()} stale domains\u2026`);
  write(`[${clock()}]   [IOC-URLs]     removing ${urlsToRemove.length.toLocaleString()} stale URLs\u2026`);
  const [domainDel, urlDel] = await Promise.all([
    deleteFromList(env, domainsToRemove),
    deleteFromUrlList(env, urlsToRemove),
  ]);
  write(
    `[${clock()}]   [IOC-Domains]  \u2713 removed ${domainDel.deleted}`,
  );
  write(
    `[${clock()}]   [IOC-URLs]     \u2713 removed ${urlDel.deleted}${urlDel.skipped > 0 ? `  (${urlDel.skipped} not found in CF \u2014 skipped)` : ``}`,
  );
  write(`[${clock()}]   [IOC-Domains]  appending ${domainsToAdd.length.toLocaleString()} new domains\u2026`);
  write(`[${clock()}]   [IOC-URLs]     appending ${urlsToAdd.length.toLocaleString()} new URLs\u2026`);
  const [domainAdd, urlAdd] = await Promise.all([appendToList(env, domainsToAdd), appendToUrlList(env, urlsToAdd)]);
  write(`[${clock()}]   [IOC-Domains]  \u2713 added ${domainAdd.added}`);
  write(
    `[${clock()}]   [IOC-URLs]     \u2713 added ${urlAdd.added}${urlAdd.skipped > 0 ? `  (${urlAdd.skipped} duplicates skipped)` : ``}`,
  );

  if (log) {
    write(`[${clock()}]`);
    write(`[${clock()}] ${LINE}`);
    write(`[${clock()}]  SYNC COMPLETE`);
    write(
      `[${clock()}]  IOC-Domains : ${(currentDomainSet.size + domainAdd.added - domainDel.deleted).toLocaleString()} total  (+${domainAdd.added} -${domainDel.deleted})`,
    );
    write(
      `[${clock()}]  IOC-URLs    : ${(currentUrlSet.size + urlAdd.added - urlDel.deleted).toLocaleString()} total  (+${urlAdd.added} -${urlDel.deleted})`,
    );
    write(`[${clock()}]  Intel skipped     : ${intelSkipped.length}`);
    write(`[${clock()}] ${LINE}`);
  }

  const elapsed = Date.now() - startMs;
  return {
    ts: new Date().toISOString(),
    elapsedMs: elapsed,
    feedStats,
    feedErrors,
    domains: {
      fresh: freshDomainSet.size,
      intelSkipped: intelSkipped.length,
      current: currentDomainSet.size,
      added: domainAdd.added,
      removed: domainDel.deleted,
      total: currentDomainSet.size + domainAdd.added - domainDel.deleted,
    },
    urls: {
      fresh: freshUrlSet.size,
      current: currentUrlSet.size,
      added: urlAdd.added,
      removed: urlDel.deleted,
      total: currentUrlSet.size + urlAdd.added - urlDel.deleted,
    },
  };
}

async function persistLastSync(env: Env, result: SyncResult): Promise<void> {
  await env.IOC_CACHE.put("last_sync", JSON.stringify(result), { expirationTtl: 86400 });
}

/** Parses KV-stored last_sync defensively; a corrupt value renders as "never synced". */
function parseSyncResult(raw: string | null): SyncResult | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SyncResult;
  } catch {
    return null;
  }
}

async function readJson<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

/** Shared body contract for the manual list-items endpoints. */
async function parseListItemsBody(
  request: Request,
): Promise<{ list: FeedListType; items: string[] } | null> {
  const body = await readJson<{ list?: string; items?: unknown }>(request);
  if (!body || (body.list !== "domain" && body.list !== "url")) return null;
  const items = body.items;
  if (!Array.isArray(items) || items.length === 0 || items.length > 1_000) return null;
  if (!items.every((x) => typeof x === "string")) return null;
  return { list: body.list, items };
}

function listIdFor(env: Env, list: FeedListType): string {
  return list === "domain" ? env.CF_LIST_ID : env.CF_URL_LIST_ID;
}

export default {
  // Cron trigger: daily at 08:00 UTC (configured in wrangler.jsonc)
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        try {
          const result = await runSync(env);
          await persistLastSync(env, result);
          console.log(
            `[ti-ioc-sync] cron complete: domains +${result.domains.added}/-${result.domains.removed}=${result.domains.total} urls +${result.urls.added}/-${result.urls.removed}=${result.urls.total} (${result.elapsedMs}ms)`,
          );
        } catch (err) {
          console.error(`[ti-ioc-sync] cron error:`, err);
        }
      })(),
    );
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Browsers request this on every page load; answer without triggering the auth gate.
    if (request.method === "GET" && url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
    }

    // Auth gate: only the dashboard and its status JSON are public. Every mutating,
    // debug, and streaming route requires the ADMIN_TOKEN secret via the X-Auth-Token
    // header (fail-closed when the secret is not configured).
    if (!isPublicRoute(request.method, url.pathname)) {
      if (!env.ADMIN_TOKEN) {
        return Response.json(
          {
            status: "error",
            error: "ADMIN_TOKEN secret is not configured \u2014 admin endpoints are disabled (fail-closed)",
          },
          { status: 503 },
        );
      }
      const provided = request.headers.get("X-Auth-Token") ?? "";
      if (!provided || !timingSafeEqual(provided, env.ADMIN_TOKEN)) return unauthorized();
    }

    if (request.method === "GET" && url.pathname === "/") {
      const lastSync = parseSyncResult(await env.IOC_CACHE.get("last_sync"));
      const config = await loadFeedConfig(env);
      return new Response(renderDashboard(lastSync, config), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    if (request.method === "GET" && url.pathname === "/api/status") {
      const lastSync = parseSyncResult(await env.IOC_CACHE.get("last_sync"));
      const activeFeeds = await getActiveFeeds(env);
      return Response.json(
        {
          status: "ok",
          worker: "ti-ioc-sync",
          feeds: activeFeeds.map((f) => ({ id: f.id, name: f.name, listType: f.listType })),
          last_sync: lastSync,
        },
        { headers: { "Cache-Control": "no-store" } },
      );
    }

    if (request.method === "GET" && url.pathname === "/api/feeds") {
      const feeds = await getFeedsWithState(env);
      return Response.json({ status: "ok", feeds });
    }

    if (request.method === "POST" && url.pathname === "/api/feeds/toggle") {
      const body = await readJson<{ id?: string; enabled?: boolean }>(request);
      if (!body || typeof body.id !== "string" || !body.id || typeof body.enabled !== "boolean") {
        return Response.json({ status: "error", error: "body must be { id: string, enabled: boolean }" }, { status: 400 });
      }
      const updated = await toggleFeed(env, body.id, body.enabled);
      if (!updated) return Response.json({ status: "error", error: `unknown feed id: ${body.id}` }, { status: 404 });
      return Response.json({ status: "ok", id: body.id, enabled: body.enabled });
    }

    if (request.method === "POST" && url.pathname === "/api/feeds/custom") {
      const body = await readJson<{ url?: string; listType?: string }>(request);
      if (!body || typeof body.url !== "string" || !body.url.trim()) {
        return Response.json({ status: "error", error: "body must be { url: string, listType: 'domain' | 'url' }" }, { status: 400 });
      }
      const result = await addCustomFeed(env, body.url.trim(), body.listType as FeedListType);
      if (!result.ok) return Response.json({ status: "error", error: result.error }, { status: 400 });
      return Response.json({ status: "ok", feed: result.feed });
    }

    if (request.method === "POST" && url.pathname === "/api/feeds/custom/remove") {
      const body = await readJson<{ id?: string }>(request);
      if (!body || typeof body.id !== "string" || !body.id) {
        return Response.json({ status: "error", error: "body must be { id: string }" }, { status: 400 });
      }
      const removed = await removeCustomFeed(env, body.id);
      if (!removed) return Response.json({ status: "error", error: `unknown custom feed id: ${body.id}` }, { status: 404 });
      return Response.json({ status: "ok", id: body.id });
    }

    if (request.method === "GET" && url.pathname === "/api/lists/items") {
      const list = url.searchParams.get("list");
      if (list !== "domain" && list !== "url") {
        return Response.json({ status: "error", error: "list must be 'domain' or 'url'" }, { status: 400 });
      }
      try {
        const values = await fetchListValues(env, listIdFor(env, list));
        const manual = await loadManualItems(env);
        const manualSet = new Set(list === "domain" ? manual.domain : manual.url);
        return Response.json({
          status: "ok",
          list,
          items: values.map((v) => ({ value: v, manual: manualSet.has(v) })),
          total: values.length,
        });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "POST" && url.pathname === "/api/lists/items") {
      const parsed = await parseListItemsBody(request);
      if (!parsed) {
        return Response.json(
          { status: "error", error: "body must be { list: 'domain' | 'url', items: string[] } (max 1,000 items)" },
          { status: 400 },
        );
      }
      try {
        const { list } = parsed;
        const current = await fetchListValues(env, listIdFor(env, list));
        const currentSet = new Set(current);
        const manual = await loadManualItems(env);
        const manualArr = list === "domain" ? manual.domain : manual.url;
        const manualSet = new Set(manualArr);
        const skipped: { value: string; reason: string }[] = [];
        const toAdd: string[] = [];
        for (const raw of parsed.items) {
          const v = raw.trim();
          if (!v) continue;
          let value: string;
          if (list === "domain") {
            if (!isValidDomain(v)) {
              skipped.push({ value: v, reason: "invalid domain" });
              continue;
            }
            if (WHITELIST.has(v.toLowerCase())) {
              skipped.push({ value: v, reason: "whitelisted domain" });
              continue;
            }
            value = v.toLowerCase();
          } else {
            const normalized = parseUrls(v);
            if (normalized.length === 0) {
              skipped.push({ value: v, reason: "invalid URL" });
              continue;
            }
            if (isWhitelistedUrl(normalized[0])) {
              skipped.push({ value: v, reason: "whitelisted host" });
              continue;
            }
            // appendToUrlList stores values lowercased; keep the manual set in the
            // same canonical form so sync diffs and duplicate checks line up.
            value = normalized[0].toLowerCase();
          }
          if (currentSet.has(value) || manualSet.has(value) || toAdd.includes(value)) {
            skipped.push({ value: v, reason: "already in list" });
            continue;
          }
          if (current.length + toAdd.length >= CF_LIST_MAX) {
            skipped.push({ value: v, reason: "list is full (5,000 items)" });
            continue;
          }
          toAdd.push(value);
        }
        if (toAdd.length > 0) {
          if (list === "domain") await appendToList(env, toAdd);
          else await appendToUrlList(env, toAdd);
          const nextManual = [...manualArr];
          for (const v of toAdd) if (!nextManual.includes(v)) nextManual.push(v);
          const next: ManualItems =
            list === "domain" ? { ...manual, domain: nextManual } : { ...manual, url: nextManual };
          await saveManualItems(env, next);
        }
        return Response.json({ status: "ok", added: toAdd.length, skipped });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "POST" && url.pathname === "/api/lists/items/remove") {
      const parsed = await parseListItemsBody(request);
      if (!parsed) {
        return Response.json(
          { status: "error", error: "body must be { list: 'domain' | 'url', items: string[] } (max 1,000 items)" },
          { status: 400 },
        );
      }
      try {
        const { list } = parsed;
        const current = await fetchListValues(env, listIdFor(env, list));
        const currentSet = new Set(current);
        const manual = await loadManualItems(env);
        const manualArr = list === "domain" ? manual.domain : manual.url;
        const requested = [...new Set(parsed.items.map((v) => v.trim()).filter(Boolean))];
        const inList = requested.filter((v) => currentSet.has(v));
        if (inList.length > 0) {
          if (list === "domain") await deleteFromList(env, inList);
          else await deleteFromUrlList(env, inList);
        }
        // Requested values leave the manual set even if they were not currently in
        // the CF list, so a later sync cannot resurrect them.
        const requestedSet = new Set(requested);
        const nextManualArr = manualArr.filter((v) => !requestedSet.has(v));
        const next: ManualItems =
          list === "domain" ? { ...manual, domain: nextManualArr } : { ...manual, url: nextManualArr };
        await saveManualItems(env, next);
        return Response.json({ status: "ok", removed: inList.length });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "GET" && url.pathname === "/sync/stream") {
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const enc = new TextEncoder();
      const write: SyncLogger = (line) => writer.write(enc.encode(line + "\n"));
      ctx.waitUntil(
        runSync(env, write)
          .catch((err) => write(`\n[ERROR] ${String(err)}`))
          .finally(() => writer.close()),
      );
      return new Response(readable, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "no-store",
          "Transfer-Encoding": "chunked",
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/sync") {
      ctx.waitUntil(
        (async () => {
          try {
            const result = await runSync(env);
            await persistLastSync(env, result);
          } catch (err) {
            console.error("[ti-ioc-sync] manual sync error:", err);
          }
        })(),
      );
      return Response.json({ status: "sync triggered \u2014 check / in a moment" });
    }

    if (request.method === "POST" && url.pathname === "/sync/run") {
      try {
        const result = await runSync(env);
        await persistLastSync(env, result);
        return Response.json({ status: "ok", result });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "GET" && url.pathname === "/debug/feed") {
      const feedId = url.searchParams.get("id");
      const allFeeds = await getFeedsWithState(env);
      const feed = allFeeds.find((f) => f.id === feedId);
      if (!feed) return Response.json({ error: `unknown feed id: ${feedId}` }, { status: 400 });
      try {
        const res = await fetch(feed.url, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; CF-TI-Sync/1.0)" },
          signal: AbortSignal.timeout(10_000),
        });
        const text = await readBodyCapped(res, MAX_FEED_BYTES);
        const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
        return Response.json({ status: res.status, totalLines: lines.length, sample: lines.slice(0, 5) });
      } catch (err) {
        return Response.json({ error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "GET" && url.pathname === "/debug/intel") {
      const domain = url.searchParams.get("domain");
      if (!domain) return Response.json({ error: "domain query param required" }, { status: 400 });
      try {
        const res = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/intel/domain?domain=${encodeURIComponent(domain)}`,
          {
            headers: { Authorization: `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" },
          },
        );
        const json = await res.json();
        return Response.json({ httpStatus: res.status, intel: json });
      } catch (err) {
        return Response.json({ error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "GET" && url.pathname === "/debug/list") {
      try {
        const raw = await debugListItems(env);
        return Response.json({ status: "ok", raw });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "POST" && url.pathname === "/bootstrap") {
      try {
        const listId = await createList(env, "CF-IOC-Domains", "Auto-synced domain IOCs from OSINT feeds", "DOMAIN");
        return Response.json({
          status: "ok",
          message: "DOMAIN list created. Run: wrangler secret put CF_LIST_ID",
          list_id: listId,
        });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "POST" && url.pathname === "/reset/url-list") {
      try {
        const { cleared } = await clearUrlList(env);
        return Response.json({
          status: "ok",
          message: `Cleared ${cleared} items. Now POST /sync/run to repopulate.`,
        });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    if (request.method === "POST" && url.pathname === "/bootstrap/url") {
      try {
        const listId = await createList(
          env,
          "CF-IOC-URLs",
          "Auto-synced URL IOCs from OSINT feeds (URLhaus, OpenPhish, VXVault)",
          "URL",
        );
        return Response.json({
          status: "ok",
          message: "URL list created. Run: wrangler secret put CF_URL_LIST_ID",
          list_id: listId,
        });
      } catch (err) {
        return Response.json({ status: "error", error: String(err) }, { status: 500 });
      }
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  },
};
