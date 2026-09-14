import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { runSync } from "../src/index";
import { FEEDS } from "../src/feeds";
import { toggleFeed } from "../src/feedconfig";
import type { Env, SyncResult } from "../src/types";

function mockKV(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: async (key: string) => store.get(key) ?? null,
    put: async (key: string, value: string) => {
      store.set(key, value);
    },
  } as unknown as KVNamespace;
}

function mockEnv(overrides: Partial<Env> = {}): Env {
  return {
    CF_ACCOUNT_ID: "acct",
    CF_API_TOKEN: "tok",
    CF_LIST_ID: "list-dom",
    CF_URL_LIST_ID: "list-url",
    ADMIN_TOKEN: "test-admin-token",
    IOC_CACHE: mockKV(),
    ...overrides,
  } as Env;
}

interface RecordedPatch {
  url: string;
  body: Record<string, unknown>;
}

interface FetchMockOptions {
  /** Feed URLs whose fetch must throw (simulated outage). */
  failingFeeds?: Set<string>;
  /** Feed URL -> response body. Unlisted feeds return a benign default. */
  feedBodies?: Record<string, string>;
  /** Items currently in the CF-IOC-Domains list. */
  currentDomains?: string[];
  /** Items currently in the CF-IOC-URLs list. */
  currentUrls?: string[];
}

function installFetchMock(opts: FetchMockOptions = {}): { patches: RecordedPatch[] } {
  const patches: RecordedPatch[] = [];
  const failing = opts.failingFeeds ?? new Set<string>();
  const bodies = opts.feedBodies ?? {};

  const stub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? "GET";

    if (url.includes("api.cloudflare.com")) {
      if (method === "PATCH") {
        patches.push({ url, body: JSON.parse(String(init?.body)) as Record<string, unknown> });
        return new Response(null, { status: 200 });
      }
      if (url.includes("/intel/")) {
        return Response.json({ success: true, result: [], errors: [] });
      }
      if (url.includes("/list-dom/")) {
        return Response.json({
          success: true,
          result: (opts.currentDomains ?? []).map((value) => ({ value })),
          result_info: { total_count: (opts.currentDomains ?? []).length },
          errors: [],
        });
      }
      return Response.json({
        success: true,
        result: (opts.currentUrls ?? []).map((value) => ({ value })),
        result_info: { total_count: (opts.currentUrls ?? []).length },
        errors: [],
      });
    }

    if (failing.has(url)) throw new Error("network unreachable");
    const feed = FEEDS.find((f) => f.url === url);
    let body = bodies[url];
    if (body === undefined) {
      if (feed?.format === "csv_threatfox") {
        body = '"2024-01-01 00:00:00","x","evilcsv.example.com:443","domain",';
      } else if (feed?.listType === "url") {
        body = "https://feedurl.example.org/x";
      } else {
        body = "ok.example.com";
      }
    }
    return new Response(body, { status: 200 });
  });

  vi.stubGlobal("fetch", stub);
  return { patches };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function removalsFrom(patches: RecordedPatch[], listId: string): string[] {
  const out: string[] = [];
  for (const p of patches) {
    if (!p.url.includes(`/gateway/lists/${listId}`)) continue;
    for (const v of (p.body.remove as string[] | undefined) ?? []) out.push(v);
  }
  return out;
}

function appendsFrom(patches: RecordedPatch[], listId: string): string[] {
  const out: string[] = [];
  for (const p of patches) {
    if (!p.url.includes(`/gateway/lists/${listId}`)) continue;
    for (const v of (p.body.append as { value: string }[] | undefined) ?? []) out.push(v.value);
  }
  return out;
}

describe("runSync fail-closed removals (audit finding src/index.ts:runSync/removal-diff-fail-open)", () => {
  it("skips removals when an active feed fails to fetch (stale cache unavailable)", async () => {
    const { patches } = installFetchMock({
      failingFeeds: new Set(["http://vxvault.net/URL_List.php"]),
      currentDomains: ["old.domain.example"],
      currentUrls: ["https://old.url.example/x"],
    });
    const result = await runSync(mockEnv());

    // Adds still proceed, but no item may be removed while a feed is unhealthy.
    expect(removalsFrom(patches, "list-dom")).toEqual([]);
    expect(removalsFrom(patches, "list-url")).toEqual([]);
    expect(appendsFrom(patches, "list-dom").length).toBeGreaterThan(0);
    expect(result.feedErrors.join(" ")).toContain("removals skipped (fail-closed)");
    expect(result.feedErrors.join(" ")).toContain("vxvault");
    expect(result.domains.removed).toBe(0);
  });

  it("skips removals when a feed returns HTTP 200 with an empty body (no error string)", async () => {
    const { patches } = installFetchMock({
      feedBodies: { "http://vxvault.net/URL_List.php": "" },
      currentDomains: ["old.domain.example"],
      currentUrls: ["https://old.url.example/x"],
    });
    const result = await runSync(mockEnv());

    expect(removalsFrom(patches, "list-dom")).toEqual([]);
    expect(removalsFrom(patches, "list-url")).toEqual([]);
    expect(result.feedErrors.join(" ")).toContain("1 feed(s) returned no items");
  });

  it("skips removals when every feed is disabled (empty fresh set must not wipe the lists)", async () => {
    const env = mockEnv();
    for (const f of FEEDS) await toggleFeed(env, f.id, false);
    const { patches } = installFetchMock({
      currentDomains: ["old.domain.example"],
      currentUrls: ["https://old.url.example/x"],
    });
    const result = await runSync(env);

    expect(removalsFrom(patches, "list-dom")).toEqual([]);
    expect(removalsFrom(patches, "list-url")).toEqual([]);
    expect(result.feedErrors.join(" ")).toContain("no active feeds");
  });

  it("removes stale items and appends new ones when all feeds are healthy", async () => {
    const { patches } = installFetchMock({
      currentDomains: ["old.domain.example"],
      currentUrls: ["https://old.url.example/x"],
    });
    const result = await runSync(mockEnv());

    expect(removalsFrom(patches, "list-dom")).toContain("old.domain.example");
    expect(removalsFrom(patches, "list-url")).toContain("https://old.url.example/x");
    expect(result.domains.removed).toBe(1);
    expect(result.urls.removed).toBe(1);
    expect(result.feedErrors.filter((e) => e.includes("fail-closed"))).toEqual([]);
  });

  it("falls back to the stale cache when a feed fails and a recent copy exists", async () => {
    const env = mockEnv();
    // Seed the feed cache as a previous successful fetch would have.
    await env.IOC_CACHE.put("feed:vxvault_urls", "https://cached.example.org/a", { expirationTtl: 172_800 });
    const { patches } = installFetchMock({
      failingFeeds: new Set(["http://vxvault.net/URL_List.php"]),
      currentDomains: ["old.domain.example"],
    });
    const result = await runSync(env);

    // Stale items count as content: the feed is not "empty", so removals are authorized.
    expect(result.feedErrors.filter((e) => e.includes("fail-closed"))).toEqual([]);
    expect(removalsFrom(patches, "list-dom")).toContain("old.domain.example");
    expect(appendsFrom(patches, "list-url")).toContain("https://cached.example.org/a");
  });
});

describe("URL-bucket whitelist enforcement (audit finding src/index.ts:WHITELIST.url-bucket-bypass)", () => {
  it("excludes whitelisted hosts and their subdomains from the URL bucket, but not lookalikes", async () => {
    const { patches } = installFetchMock({
      feedBodies: {
        "https://openphish.com/feed.txt":
          "https://microsoft.com/login\nhttps://login.microsoft.com/x\nhttps://evil.example.org/a\nhttps://microsoft.com.evil.io/b",
      },
    });
    await runSync(mockEnv());

    const appended = appendsFrom(patches, "list-url");
    expect(appended).toContain("https://evil.example.org/a");
    expect(appended).toContain("https://microsoft.com.evil.io/b");
    expect(appended).not.toContain("https://microsoft.com/login");
    expect(appended).not.toContain("https://login.microsoft.com/x");
  });
});

describe("HTTP auth gate (audit finding src/index.ts:unauth-mutating-routes)", () => {
  const ctx = { waitUntil: () => undefined } as unknown as ExecutionContext;

  it("keeps GET / and GET /api/status public", async () => {
    installFetchMock();
    const env = mockEnv();
    const home = await worker.fetch(new Request("http://x/"), env, ctx);
    const status = await worker.fetch(new Request("http://x/api/status"), env, ctx);
    expect(home.status).toBe(200);
    expect((status as Response).status ? status.status : 0).toBe(200);
  });

  it("rejects protected routes without a token", async () => {
    installFetchMock();
    const env = mockEnv();
    const res = await worker.fetch(new Request("http://x/sync/run", { method: "POST" }), env, ctx);
    expect(res.status).toBe(401);
  });

  it("rejects a wrong token (constant-time compare path)", async () => {
    installFetchMock();
    const env = mockEnv();
    const res = await worker.fetch(
      new Request("http://x/api/feeds", { headers: { "X-Auth-Token": "wrong-token" } }),
      env,
      ctx,
    );
    expect(res.status).toBe(401);
  });

  it("accepts a valid token on a protected route", async () => {
    installFetchMock();
    const env = mockEnv();
    const res = await worker.fetch(
      new Request("http://x/api/feeds", { headers: { "X-Auth-Token": "test-admin-token" } }),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { status: string; feeds: unknown[] };
    expect(data.status).toBe("ok");
    expect(data.feeds.length).toBe(9);
  });

  it("fails closed with 503 when ADMIN_TOKEN is not configured", async () => {
    installFetchMock();
    const env = mockEnv({ ADMIN_TOKEN: "" });
    const res = await worker.fetch(new Request("http://x/api/feeds"), env, ctx);
    expect(res.status).toBe(503);
  });

  it("rejects the state-changing GET /sync/stream without a token", async () => {
    installFetchMock();
    const env = mockEnv();
    const res = await worker.fetch(new Request("http://x/sync/stream"), env, ctx);
    expect(res.status).toBe(401);
  });

  it("treats a corrupt last_sync KV value as never-synced instead of throwing", async () => {
    installFetchMock();
    const env = mockEnv();
    await env.IOC_CACHE.put("last_sync", "{not json");
    const status = await worker.fetch(new Request("http://x/api/status"), env, ctx);
    expect(status.status).toBe(200);
    const data = (await status.json()) as { last_sync: SyncResult | null };
    expect(data.last_sync).toBeNull();
  });
});
