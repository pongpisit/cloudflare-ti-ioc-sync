import type { CfApiEnvelope, CfListItem, Env } from "./types";

const CF_BASE = "https://api.cloudflare.com/client/v4";
const CHUNK_SIZE = 1_000;
const CHUNK_DELAY_MS = 300;
const RETRY_DELAY_MS = 50;

function headers(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function chunkLabel(i: number): number {
  return Math.floor(i / CHUNK_SIZE) + 1;
}

async function fetchListItemsPage(
  env: Env,
  listId: string,
  page: number,
): Promise<CfApiEnvelope<CfListItem[]>> {
  const url = `${CF_BASE}/accounts/${env.CF_ACCOUNT_ID}/gateway/lists/${listId}/items?page=${page}&per_page=${CHUNK_SIZE}`;
  const res = await fetch(url, { headers: headers(env.CF_API_TOKEN) });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`CF GET list items page ${page} failed: ${res.status} ${body}`);
  }
  return (await res.json()) as CfApiEnvelope<CfListItem[]>;
}

async function fetchAllListItems(env: Env, listId: string): Promise<CfListItem[]> {
  const items: CfListItem[] = [];
  let page = 1;
  for (;;) {
    const json = await fetchListItemsPage(env, listId, page);
    const pageItems = json.result ?? [];
    items.push(...pageItems);
    const total = json.result_info?.total_count ?? 0;
    if (page * CHUNK_SIZE >= total || pageItems.length < CHUNK_SIZE) break;
    page++;
  }
  return items;
}

async function patchList(env: Env, listId: string, body: Record<string, unknown>): Promise<Response> {
  return fetch(`${CF_BASE}/accounts/${env.CF_ACCOUNT_ID}/gateway/lists/${listId}`, {
    method: "PATCH",
    headers: headers(env.CF_API_TOKEN),
    body: JSON.stringify(body),
  });
}

export async function getListItems(env: Env): Promise<Set<string>> {
  const items = await fetchAllListItems(env, env.CF_LIST_ID);
  return new Set(items.map((item) => item.value.toLowerCase()));
}

export async function debugListItems(env: Env): Promise<unknown> {
  const url = `${CF_BASE}/accounts/${env.CF_ACCOUNT_ID}/gateway/lists/${env.CF_LIST_ID}/items?page=1&per_page=5`;
  const res = await fetch(url, { headers: headers(env.CF_API_TOKEN) });
  return res.json();
}

export async function appendToList(env: Env, domains: string[]): Promise<{ added: number }> {
  if (domains.length === 0) return { added: 0 };
  let added = 0;
  for (let i = 0; i < domains.length; i += CHUNK_SIZE) {
    const chunk = domains.slice(i, i + CHUNK_SIZE);
    const res = await patchList(env, env.CF_LIST_ID, {
      append: chunk.map((d) => ({ value: d })),
    });
    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`CF PATCH append failed (chunk ${chunkLabel(i)}): ${res.status} ${errBody}`);
    }
    added += chunk.length;
    if (i + CHUNK_SIZE < domains.length) await sleep(CHUNK_DELAY_MS);
  }
  return { added };
}

export async function deleteFromList(env: Env, domains: string[]): Promise<{ deleted: number }> {
  if (domains.length === 0) return { deleted: 0 };
  let deleted = 0;
  for (let i = 0; i < domains.length; i += CHUNK_SIZE) {
    const chunk = domains.slice(i, i + CHUNK_SIZE);
    const res = await patchList(env, env.CF_LIST_ID, { remove: chunk });
    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`CF PATCH remove failed (chunk ${chunkLabel(i)}): ${res.status} ${errBody}`);
    }
    deleted += chunk.length;
    if (i + CHUNK_SIZE < domains.length) await sleep(CHUNK_DELAY_MS);
  }
  return { deleted };
}

export async function createList(
  env: Env,
  name: string,
  description: string,
  type = "DOMAIN",
): Promise<string> {
  const res = await fetch(`${CF_BASE}/accounts/${env.CF_ACCOUNT_ID}/gateway/lists`, {
    method: "POST",
    headers: headers(env.CF_API_TOKEN),
    body: JSON.stringify({ name, description, type }),
  });
  const json = (await res.json()) as CfApiEnvelope<{ id: string }>;
  if (!json.success || !json.result) {
    throw new Error(`Failed to create list: ${JSON.stringify(json.errors)}`);
  }
  return json.result.id;
}

export async function getUrlListItems(env: Env): Promise<Set<string>> {
  const items = await fetchAllListItems(env, env.CF_URL_LIST_ID);
  return new Set(items.map((item) => item.value.toLowerCase()));
}

export async function appendToUrlList(
  env: Env,
  items: string[],
): Promise<{ added: number; skipped: number }> {
  if (items.length === 0) return { added: 0, skipped: 0 };
  let added = 0;
  let skipped = 0;
  for (let i = 0; i < items.length; i += CHUNK_SIZE) {
    const chunk = items.slice(i, i + CHUNK_SIZE);
    const res = await patchList(env, env.CF_URL_LIST_ID, {
      append: chunk.map((v) => ({ value: v.toLowerCase() })),
    });
    if (res.ok) {
      added += chunk.length;
    } else {
      const errBody = await res.text();
      const is409 = res.status === 409 || errBody.includes("1204") || errBody.includes("already exists");
      if (is409) {
        // Retry one-by-one: a single duplicate fails the whole chunk on the URL list
        for (const value of chunk) {
          const r = await patchList(env, env.CF_URL_LIST_ID, {
            append: [{ value: value.toLowerCase() }],
          });
          if (r.ok) {
            added++;
          } else {
            skipped++;
          }
          await sleep(RETRY_DELAY_MS);
        }
      } else {
        throw new Error(`CF PATCH url-list append failed (chunk ${chunkLabel(i)}): ${res.status} ${errBody}`);
      }
    }
    if (i + CHUNK_SIZE < items.length) await sleep(CHUNK_DELAY_MS);
  }
  return { added, skipped };
}

export async function deleteFromUrlList(
  env: Env,
  items: string[],
): Promise<{ deleted: number; skipped: number }> {
  if (items.length === 0) return { deleted: 0, skipped: 0 };
  let deleted = 0;
  let skipped = 0;
  for (let i = 0; i < items.length; i += CHUNK_SIZE) {
    const chunk = items.slice(i, i + CHUNK_SIZE);
    const res = await patchList(env, env.CF_URL_LIST_ID, { remove: chunk });
    if (res.ok) {
      deleted += chunk.length;
    } else {
      // Retry one-by-one: removing an item that is not in the list fails the chunk
      for (const value of chunk) {
        const ok = await removeUrlListSingle(env, value);
        if (ok) {
          deleted++;
        } else {
          skipped++;
        }
        await sleep(RETRY_DELAY_MS);
      }
    }
    if (i + CHUNK_SIZE < items.length) await sleep(CHUNK_DELAY_MS);
  }
  return { deleted, skipped };
}

async function removeUrlListSingle(env: Env, value: string): Promise<boolean> {
  const res = await patchList(env, env.CF_URL_LIST_ID, { remove: [value] });
  return res.ok;
}

export async function clearUrlList(env: Env): Promise<{ cleared: number }> {
  const all = await fetchAllListItems(env, env.CF_URL_LIST_ID);
  const values = all.map((item) => item.value);
  if (values.length === 0) return { cleared: 0 };
  for (let i = 0; i < values.length; i += CHUNK_SIZE) {
    const chunk = values.slice(i, i + CHUNK_SIZE);
    const res = await patchList(env, env.CF_URL_LIST_ID, { remove: chunk });
    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`CF PATCH url-list clear failed (chunk ${chunkLabel(i)}): ${res.status} ${errBody}`);
    }
    if (i + CHUNK_SIZE < values.length) await sleep(CHUNK_DELAY_MS);
  }
  return { cleared: values.length };
}
