import { parseFeed } from "./feeds";
import {
  appendToList,
  appendToUrlList,
  clearUrlList,
  createList,
  debugListItems,
  deleteFromList,
  deleteFromUrlList,
  getListItems,
  getUrlListItems,
} from "./cfapi";
import { filterCfKnownThreats } from "./intel";
import { renderDashboard } from "./dashboard";
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
const USER_AGENT = "Mozilla/5.0 (compatible; CF-TI-Sync/1.0; +https://ti-ioc-sync.pongpisit.workers.dev)";

// Exact-match whitelist of high-trust domains excluded from the domain list
const WHITELIST = new Set([
  "cloudflare.com",
  "microsoft.com",
  "windows.com",
  "office.com",
  "google.com",
  "apple.com",
  "akamai.net",
  "fastly.net",
]);

function capItems(feed: Feed, items: string[]): string[] {
  return feed.maxDomains ? items.slice(0, feed.maxDomains) : items;
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
      rawJson = await res.json();
    } else {
      const res = await fetch(feed.url, {
        headers: { "User-Agent": USER_AGENT },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      rawText = await res.text();
    }
    const toCache = rawJson ? JSON.stringify(rawJson) : rawText;
    await cacheKV.put(cacheKey, toCache, { expirationTtl: 300 });
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
 */
async function runSync(env: Env, log?: SyncLogger): Promise<SyncResult> {
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
  for (const { feedId, items, listType, error } of results) {
    feedStats[feedId] = items.length;
    if (error) feedErrors.push(`${feedId}: ${error}`);
    if (error && items.length === 0) continue;
    if (listType === "url") {
      freshUrls.push(...items);
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
  const freshDomainSet = new Set(freshDomains.slice(0, CF_LIST_MAX * 2));
  const freshDomainCapped = [...freshDomainSet].slice(0, CF_LIST_MAX);
  const freshUrlSet = new Set(freshUrls.slice(0, CF_LIST_MAX * 2));
  const freshUrlCapped = [...freshUrlSet].slice(0, CF_LIST_MAX);

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

  // Diff — URLs are compared after percent-decoding so encoded duplicates are caught
  const freshDomainSetCapped = new Set(freshDomainCapped);
  const rawDomainsToAdd = freshDomainCapped.filter((d) => !currentDomainSet.has(d));
  const domainsToRemove = [...currentDomainSet].filter((d) => !freshDomainSetCapped.has(d));
  const freshUrlNorm = new Set(freshUrlCapped.map(tryDecode));
  const currentUrlNorm = new Map([...currentUrlSet].map((u) => [tryDecode(u), u]));
  const urlsToAdd = freshUrlCapped.filter((u) => !currentUrlNorm.has(tryDecode(u)));
  const urlsToRemove = [...currentUrlSet].filter((u) => !freshUrlNorm.has(tryDecode(u)));

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

async function readJson<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
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

    if (request.method === "GET" && url.pathname === "/") {
      const lastSyncRaw = await env.IOC_CACHE.get("last_sync");
      const lastSync = lastSyncRaw ? (JSON.parse(lastSyncRaw) as SyncResult) : null;
      const config = await loadFeedConfig(env);
      return new Response(renderDashboard(lastSync, config), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (request.method === "GET" && url.pathname === "/api/status") {
      const lastSyncRaw = await env.IOC_CACHE.get("last_sync");
      const activeFeeds = await getActiveFeeds(env);
      return Response.json({
        status: "ok",
        worker: "ti-ioc-sync",
        feeds: activeFeeds.map((f) => ({ id: f.id, name: f.name, listType: f.listType })),
        last_sync: lastSyncRaw ? JSON.parse(lastSyncRaw) : null,
      });
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
        const text = await res.text();
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
