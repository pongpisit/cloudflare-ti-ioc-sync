import type { CfIntelDomainInfo, Env, IntelFilterResult } from "./types";

const CF_BASE = "https://api.cloudflare.com/client/v4";

// Cloudflare Radar / Intel category IDs treated as "already known threats".
const THREAT_CATEGORY_IDS = new Set<number>([
  // Security Threats (super-category)
  117, // Malware
  131, // Phishing
  80, // Command and Control & Botnet
  83, // Cryptomining
  15, // Compromised Domains
  176, // DGA Domains
  175, // DNS Tunneling
  68, // Anonymizer
  153, // Brand Embedding
  108, // Potentially Unwanted Software
  128, // Private IP Address
  196, // Scam
  169, // Spam
  178, // Spyware
  // Parent "Security Threats" super-category
  127, // Security Threats (umbrella)
]);

const INTEL_CACHE_TTL = 6 * 60 * 60;
const INTEL_CHUNK = 200;
const CHUNK_DELAY_MS = 200;

export function isCfThreat(info: CfIntelDomainInfo): boolean {
  const riskIds = (info.risk_types ?? []).map((r) => r.id);
  const contentIds = (info.content_categories ?? []).map((c) => c.id);
  for (const id of [...riskIds, ...contentIds]) {
    if (THREAT_CATEGORY_IDS.has(id)) return true;
  }
  return false;
}

export interface IntelProgress {
  onChunk?: (message: string) => void;
  onSkipped?: (details: { domain: string; riskTypeIds: string }[]) => void;
}

export async function filterCfKnownThreats(
  env: Env,
  domains: string[],
  progress?: IntelProgress,
): Promise<IntelFilterResult> {
  const kept: string[] = [];
  const skipped: string[] = [];
  const errors: string[] = [];
  const skippedDetails: { domain: string; riskTypeIds: string }[] = [];
  if (domains.length === 0) return { kept, skipped, errors, skippedDetails };

  for (let i = 0; i < domains.length; i += INTEL_CHUNK) {
    const chunk = domains.slice(i, i + INTEL_CHUNK);
    const chunkNum = Math.floor(i / INTEL_CHUNK) + 1;
    const totalChunks = Math.ceil(domains.length / INTEL_CHUNK);
    const uncached: string[] = [];
    const cachedResults = new Map<string, boolean>();

    await Promise.all(
      chunk.map(async (d) => {
        const cached = await env.IOC_CACHE.get(`intel:${d}`);
        if (cached !== null) {
          cachedResults.set(d, cached === "1");
        } else {
          uncached.push(d);
        }
      }),
    );
    for (const d of chunk) {
      if (!cachedResults.has(d)) continue;
      if (cachedResults.get(d)) {
        skipped.push(d);
      } else {
        kept.push(d);
      }
    }

    if (uncached.length > 0) {
      progress?.onChunk?.(
        `Chunk ${chunkNum}/${totalChunks} — querying CF Intel API for ${uncached.length} domains ` +
          `(${chunk.length - uncached.length} from cache)`,
      );
      try {
        const qs = uncached.map((d) => `domain=${encodeURIComponent(d)}`).join("&");
        const res = await fetch(`${CF_BASE}/accounts/${env.CF_ACCOUNT_ID}/intel/domain/bulk?${qs}`, {
          method: "GET",
          headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
          signal: AbortSignal.timeout(15_000),
        });
        if (!res.ok) {
          const errText = await res.text();
          errors.push(
            `Intel API chunk ${chunkNum}: HTTP ${res.status} ${errText}`,
          );
          kept.push(...uncached);
          continue;
        }
        const json = (await res.json()) as {
          success?: boolean;
          result?: CfIntelDomainInfo[];
          errors?: unknown;
        };
        if (!json.success || !json.result) {
          errors.push(`Intel API chunk ${chunkNum}: ${JSON.stringify(json.errors)}`);
          kept.push(...uncached);
          continue;
        }
        const resultMap = new Map<string, CfIntelDomainInfo>();
        for (const r of json.result) resultMap.set(r.domain.toLowerCase(), r);

        const chunkSkippedDetails: { domain: string; riskTypeIds: string }[] = [];
        await Promise.all(
          uncached.map(async (d) => {
            const info = resultMap.get(d.toLowerCase());
            const threat = info ? isCfThreat(info) : false;
            await env.IOC_CACHE.put(`intel:${d}`, threat ? "1" : "0", {
              expirationTtl: INTEL_CACHE_TTL,
            });
            if (threat) {
              skipped.push(d);
              chunkSkippedDetails.push({
                domain: d,
                riskTypeIds: (info?.risk_types ?? []).map((r) => r.id).join(","),
              });
            } else {
              kept.push(d);
            }
          }),
        );
        if (chunkSkippedDetails.length > 0) {
          progress?.onChunk?.(
            `→ ${chunkSkippedDetails.length} domains SKIPPED (already in CF threat categories), ` +
              `${uncached.length - chunkSkippedDetails.length} kept`,
          );
          progress?.onSkipped?.(chunkSkippedDetails);
          skippedDetails.push(...chunkSkippedDetails);
        } else {
          progress?.onChunk?.(`→ All ${uncached.length} domains kept (none pre-categorised by CF)`);
        }
      } catch (err) {
        errors.push(`Intel API chunk ${chunkNum}: ${String(err)}`);
        kept.push(...uncached);
      }
    } else if (progress?.onChunk) {
      progress.onChunk(
        `Chunk ${chunkNum}/${totalChunks} — all ${chunk.length} from KV cache (no API call needed)`,
      );
    }

    if (i + INTEL_CHUNK < domains.length) await sleep(CHUNK_DELAY_MS);
  }
  return { kept, skipped, errors, skippedDetails };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
