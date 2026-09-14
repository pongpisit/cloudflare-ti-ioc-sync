import type { Env } from "./types";

const MANUAL_ITEMS_KEY = "manual_items";

export interface ManualItems {
  domain: string[];
  url: string[];
}

/**
 * Manually added list items (KV key `manual_items`). They are merged into the sync
 * pipeline's fresh sets ahead of feed content, so neither the 5,000-item cap nor the
 * removal diff can drop them: manual items survive syncs.
 */
export async function loadManualItems(env: Env): Promise<ManualItems> {
  const raw = await env.IOC_CACHE.get(MANUAL_ITEMS_KEY);
  if (!raw) return { domain: [], url: [] };
  try {
    const parsed = JSON.parse(raw) as Partial<ManualItems>;
    return {
      domain: Array.isArray(parsed.domain)
        ? parsed.domain.filter((x): x is string => typeof x === "string")
        : [],
      url: Array.isArray(parsed.url) ? parsed.url.filter((x): x is string => typeof x === "string") : [],
    };
  } catch {
    return { domain: [], url: [] };
  }
}

export async function saveManualItems(env: Env, items: ManualItems): Promise<void> {
  await env.IOC_CACHE.put(MANUAL_ITEMS_KEY, JSON.stringify(items));
}
