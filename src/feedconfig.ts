import { FEEDS } from "./feeds";
import type { Env, Feed, FeedConfig, FeedListType } from "./types";

const FEED_CONFIG_KEY = "feed_config";
export const MAX_CUSTOM_FEEDS = 10;
export const CUSTOM_FEED_MAX_ITEMS = 500;

// Only plain-text .txt lists are accepted (optionally followed by a query string / fragment)
const TXT_URL_RE = /^https?:\/\/[^\s?#]+\.txt([?#]\S*)?$/i;

function isValidListType(v: unknown): v is FeedListType {
  return v === "domain" || v === "url";
}

function isValidFeed(f: unknown): f is Feed {
  if (typeof f !== "object" || f === null) return false;
  const feed = f as Record<string, unknown>;
  return (
    typeof feed.id === "string" &&
    typeof feed.name === "string" &&
    typeof feed.url === "string" &&
    feed.format === "plain" &&
    isValidListType(feed.listType)
  );
}

export async function loadFeedConfig(env: Env): Promise<FeedConfig> {
  const raw = await env.IOC_CACHE.get(FEED_CONFIG_KEY);
  if (!raw) return { disabled: [], custom: [] };
  try {
    const parsed = JSON.parse(raw) as Partial<FeedConfig>;
    return {
      disabled: Array.isArray(parsed.disabled)
        ? parsed.disabled.filter((x): x is string => typeof x === "string")
        : [],
      custom: Array.isArray(parsed.custom) ? parsed.custom.filter(isValidFeed) : [],
    };
  } catch {
    return { disabled: [], custom: [] };
  }
}

async function saveFeedConfig(env: Env, cfg: FeedConfig): Promise<void> {
  await env.IOC_CACHE.put(FEED_CONFIG_KEY, JSON.stringify(cfg));
}

export function isValidCustomFeedUrl(url: string): boolean {
  return TXT_URL_RE.test(url);
}

/** All feeds (built-in + custom) with their enabled state — used by API and dashboard. */
export async function getFeedsWithState(
  env: Env,
): Promise<(Feed & { enabled: boolean; custom: boolean })[]> {
  const cfg = await loadFeedConfig(env);
  return [
    ...FEEDS.map((f) => ({ ...f, enabled: !cfg.disabled.includes(f.id), custom: false })),
    ...cfg.custom.map((f) => ({ ...f, enabled: !cfg.disabled.includes(f.id), custom: true })),
  ];
}

/** Feeds that should actually be fetched on the next sync. */
export async function getActiveFeeds(env: Env): Promise<Feed[]> {
  const cfg = await loadFeedConfig(env);
  const all = [...FEEDS, ...cfg.custom];
  return all.filter((f) => !cfg.disabled.includes(f.id));
}

export async function toggleFeed(env: Env, id: string, enabled: boolean): Promise<boolean> {
  const cfg = await loadFeedConfig(env);
  const known = [...FEEDS, ...cfg.custom].some((f) => f.id === id);
  if (!known) return false;
  const disabled = new Set(cfg.disabled);
  if (enabled) {
    disabled.delete(id);
  } else {
    disabled.add(id);
  }
  await saveFeedConfig(env, { ...cfg, disabled: [...disabled] });
  return true;
}

export async function addCustomFeed(
  env: Env,
  url: string,
  listType: FeedListType,
): Promise<{ ok: true; feed: Feed } | { ok: false; error: string }> {
  if (!isValidCustomFeedUrl(url)) {
    return { ok: false, error: "Only .txt plain-text list URLs are accepted (https://…/name.txt)" };
  }
  if (!isValidListType(listType)) {
    return { ok: false, error: "listType must be 'domain' or 'url'" };
  }
  const cfg = await loadFeedConfig(env);
  const duplicate = [...FEEDS, ...cfg.custom].some((f) => f.url === url);
  if (duplicate) {
    return { ok: false, error: "This feed URL already exists" };
  }
  if (cfg.custom.length >= MAX_CUSTOM_FEEDS) {
    return { ok: false, error: `Custom feed limit reached (${MAX_CUSTOM_FEEDS})` };
  }
  let host = url;
  try {
    host = new URL(url).hostname;
  } catch {
    // validated above; keep url as name fallback
  }
  const feed: Feed = {
    id: `custom_${Date.now().toString(36)}`,
    name: `${host} (custom .txt)`,
    url,
    format: "plain",
    listType,
    maxDomains: CUSTOM_FEED_MAX_ITEMS,
  };
  await saveFeedConfig(env, { ...cfg, custom: [...cfg.custom, feed] });
  return { ok: true, feed };
}

export async function removeCustomFeed(env: Env, id: string): Promise<boolean> {
  const cfg = await loadFeedConfig(env);
  const before = cfg.custom.length;
  const custom = cfg.custom.filter((f) => f.id !== id);
  if (custom.length === before) return false;
  await saveFeedConfig(env, { ...cfg, custom, disabled: cfg.disabled.filter((d) => d !== id) });
  return true;
}
