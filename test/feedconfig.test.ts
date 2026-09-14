import { beforeEach, describe, expect, it } from "vitest";
import {
  addCustomFeed,
  CUSTOM_FEED_MAX_ITEMS,
  getActiveFeeds,
  getFeedsWithState,
  isValidCustomFeedUrl,
  loadFeedConfig,
  removeCustomFeed,
  toggleFeed,
} from "../src/feedconfig";
import type { Env, FeedConfig } from "../src/types";

function mockKV(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: async (key: string) => store.get(key) ?? null,
    put: async (key: string, value: string) => {
      store.set(key, value);
    },
  } as unknown as KVNamespace;
}

function mockEnv(): Env {
  return { IOC_CACHE: mockKV() } as unknown as Env;
}

let env: Env;
beforeEach(() => {
  env = mockEnv();
});

describe("isValidCustomFeedUrl", () => {
  it("accepts .txt urls", () => {
    expect(isValidCustomFeedUrl("https://example.com/list.txt")).toBe(true);
    expect(isValidCustomFeedUrl("http://example.com/list.txt")).toBe(true);
    expect(isValidCustomFeedUrl("https://example.com/list.txt?download=1")).toBe(true);
  });

  it("rejects non-txt urls and garbage", () => {
    expect(isValidCustomFeedUrl("https://example.com/list.csv")).toBe(false);
    expect(isValidCustomFeedUrl("https://example.com/txtfile")).toBe(false);
    expect(isValidCustomFeedUrl("ftp://example.com/list.txt")).toBe(false);
    expect(isValidCustomFeedUrl("not a url")).toBe(false);
    expect(isValidCustomFeedUrl("")).toBe(false);
  });
});

describe("addCustomFeed", () => {
  it("adds a validated .txt feed with capped item limit", async () => {
    const result = await addCustomFeed(env, "https://example.com/blocklist.txt", "domain");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.feed.id).toMatch(/^custom_/);
      expect(result.feed.format).toBe("plain");
      expect(result.feed.maxDomains).toBe(CUSTOM_FEED_MAX_ITEMS);
      expect(result.feed.url).toBe("https://example.com/blocklist.txt");
    }
    const active = await getActiveFeeds(env);
    expect(active.some((f) => f.id.startsWith("custom_"))).toBe(true);
  });

  it("rejects non-txt urls without saving", async () => {
    const result = await addCustomFeed(env, "https://example.com/list.csv", "domain");
    expect(result.ok).toBe(false);
    const cfg = await loadFeedConfig(env);
    expect(cfg.custom).toHaveLength(0);
  });

  it("rejects invalid listType", async () => {
    const result = await addCustomFeed(env, "https://example.com/list.txt", "bogus" as never);
    expect(result.ok).toBe(false);
  });

  it("rejects duplicate urls (including built-ins)", async () => {
    const first = await addCustomFeed(env, "https://example.com/list.txt", "domain");
    expect(first.ok).toBe(true);
    const dup = await addCustomFeed(env, "https://example.com/list.txt", "domain");
    expect(dup.ok).toBe(false);
    const builtinDup = await addCustomFeed(env, "https://openphish.com/feed.txt", "url");
    expect(builtinDup.ok).toBe(false);
  });

  it("enforces the custom feed limit", async () => {
    for (let i = 0; i < 10; i++) {
      const r = await addCustomFeed(env, `https://example.com/feed-${i}.txt`, "domain");
      expect(r.ok).toBe(true);
    }
    const overflow = await addCustomFeed(env, "https://example.com/feed-11.txt", "domain");
    expect(overflow.ok).toBe(false);
  });
});

describe("toggleFeed", () => {
  it("disables and re-enables built-in feeds", async () => {
    expect(await toggleFeed(env, "oisd_big", false)).toBe(true);
    let active = await getActiveFeeds(env);
    expect(active.some((f) => f.id === "oisd_big")).toBe(false);
    expect(await toggleFeed(env, "oisd_big", true)).toBe(true);
    active = await getActiveFeeds(env);
    expect(active.some((f) => f.id === "oisd_big")).toBe(true);
  });

  it("returns false for unknown ids", async () => {
    expect(await toggleFeed(env, "nope", false)).toBe(false);
  });

  it("toggles custom feeds too", async () => {
    await addCustomFeed(env, "https://example.com/list.txt", "domain");
    const cfgBefore = await loadFeedConfig(env);
    const id = cfgBefore.custom[0].id;
    await toggleFeed(env, id, false);
    const active = await getActiveFeeds(env);
    expect(active.some((f) => f.id === id)).toBe(false);
  });
});

describe("getFeedsWithState", () => {
  it("reports enabled state and custom flag", async () => {
    await toggleFeed(env, "oisd_big", false);
    await addCustomFeed(env, "https://example.com/list.txt", "url");
    const feeds = await getFeedsWithState(env);
    const oisd = feeds.find((f) => f.id === "oisd_big")!;
    expect(oisd.enabled).toBe(false);
    expect(oisd.custom).toBe(false);
    const custom = feeds.find((f) => f.custom)!;
    expect(custom.enabled).toBe(true);
    expect(custom.url).toBe("https://example.com/list.txt");
  });
});

describe("loadFeedConfig", () => {
  it("returns empty config when nothing stored", async () => {
    const cfg = await loadFeedConfig(env);
    expect(cfg).toEqual({ disabled: [], custom: [] });
  });

  it("tolerates corrupt KV data", async () => {
    await env.IOC_CACHE.put("feed_config", "{not json");
    const cfg: FeedConfig = await loadFeedConfig(env);
    expect(cfg.disabled).toEqual([]);
    expect(cfg.custom).toEqual([]);
  });
});

describe("removeCustomFeed", () => {
  it("removes only custom feeds", async () => {
    await addCustomFeed(env, "https://example.com/list.txt", "domain");
    const cfg = await loadFeedConfig(env);
    const id = cfg.custom[0].id;
    expect(await removeCustomFeed(env, id)).toBe(true);
    expect((await loadFeedConfig(env)).custom).toHaveLength(0);
    expect(await removeCustomFeed(env, id)).toBe(false);
    expect(await removeCustomFeed(env, "urlhaus_urls")).toBe(false);
  });
});
