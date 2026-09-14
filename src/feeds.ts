import type { Feed } from "./types";

export const FEEDS: Feed[] = [
  // ──────────────────────────────────────────────────────────────
  // URL FEEDS — full URLs kept intact (synced to CF-IOC-URLs)
  // ──────────────────────────────────────────────────────────────
  // ── Abuse.ch URLhaus — active malware distribution URLs ──────────
  {
    id: "urlhaus_urls",
    name: "Abuse.ch URLhaus (online malware URLs)",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
    format: "plain",
    listType: "url",
    maxDomains: 3_000,
  },
  // ── OpenPhish — verified phishing URLs (free tier) ───────────────
  {
    id: "openphish_urls",
    name: "OpenPhish (phishing URLs)",
    url: "https://openphish.com/feed.txt",
    format: "plain",
    listType: "url",
    maxDomains: 300,
  },
  // ── VXVault — active malware URLs ────────────────────────────────
  {
    id: "vxvault_urls",
    name: "VXVault (malware URLs)",
    url: "http://vxvault.net/URL_List.php",
    format: "plain",
    listType: "url",
  },
  // ──────────────────────────────────────────────────────────────
  // DOMAIN FEEDS — bare hostnames (synced to CF-IOC-Domains)
  // ──────────────────────────────────────────────────────────────
  // ── Abuse.ch ThreatFox — C2/malware domain IOCs (CSV, last 30d) ──
  {
    id: "threatfox_domains",
    name: "Abuse.ch ThreatFox (domain CSV, last 30d)",
    url: "https://threatfox.abuse.ch/export/csv/domains/recent/",
    format: "csv_threatfox",
    listType: "domain",
  },
  // ── Cert.PL — Polish CERT phishing domain list (v2) ────────────────────
  {
    id: "certpl_phishing",
    name: "CERT.PL Phishing domains",
    url: "https://hole.cert.pl/domains/v2/domains.txt",
    format: "plain",
    listType: "domain",
    maxDomains: 500,
  },
  // ── URLhaus domain extract — active malware domains ───────────────
  {
    id: "malwaredomains",
    name: "Malware Domain List (active)",
    url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt",
    format: "plain",
    listType: "domain",
  },
  // ── OISD Big — malware + phishing domains (capped) ────────────────
  {
    id: "oisd_big",
    name: "OISD Big (malware/phishing domains)",
    url: "https://big.oisd.nl/domainswild2",
    format: "plain",
    listType: "domain",
    maxDomains: 500,
  },
  // ── Hagezi TIF — threat intelligence domain list (capped; mini variant,
  //    wildcard format — extractDomain strips the leading "*.") ─────────
  {
    id: "hagezi_threat",
    name: "Hagezi Threat Intelligence domains",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt",
    format: "plain",
    listType: "domain",
    maxDomains: 1_000,
  },
];

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function isValidDomain(d: string): boolean {
  return DOMAIN_RE.test(d) && d.length <= 253;
}

export function extractDomain(raw: string): string {
  try {
    const s = raw.includes("://") ? raw : `http://${raw}`;
    return new URL(s).hostname.replace(/^\*\./, "").toLowerCase();
  } catch {
    return raw.trim().toLowerCase();
  }
}

export function parsePlain(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith(";"))
    .map(extractDomain)
    .filter(isValidDomain);
}

const URL_RE = /^https?:\/\/.{4}/i;

export function parseUrls(text: string): string[] {
  const urls: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    if (!URL_RE.test(line) && !line.includes("://")) continue;
    try {
      const u = new URL(line.includes("://") ? line : `http://${line}`);
      if (!u.hostname) continue;
      // Wildcard hosts (e.g. https://*.microsoft.com/) are never valid feed entries:
      // reject them rather than letting shaped values reach the Gateway list API.
      if (u.hostname.includes("*")) continue;
      const schemeHost = `${u.protocol}//${u.host}`.toLowerCase();
      // indexOf is case-sensitive; URL parsing lowercases the host, so search case-insensitively
      const hostIdx = line.toLowerCase().indexOf(u.host);
      const rest = hostIdx >= 0 ? line.slice(hostIdx + u.host.length) : "";
      const normalised = (schemeHost + rest).replace(/\/+$/, "").replace(/#.*$/, "");
      urls.push(normalised);
    } catch {
      // skip unparseable lines
    }
  }
  return urls;
}

interface ThreatFoxEntry {
  ioc_type?: string;
  ioc?: string;
}

export function parseThreatFox(json: unknown): string[] {
  const data = (json as { data?: unknown } | null)?.data;
  if (!Array.isArray(data)) return [];
  return (data as ThreatFoxEntry[])
    .filter((e) => e.ioc_type === "domain")
    .map((e) => extractDomain((e.ioc ?? "").split(":")[0]))
    .filter(isValidDomain);
}

export function parseThreatFoxCsv(text: string): string[] {
  const domains: string[] = [];
  for (const rawLine of text.split("\n")) {
    const trimmed = rawLine.replace(/\r$/, "").trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith('"first_seen')) continue;
    const cols = trimmed
      .split(/",\s*"/)
      .map((c) => c.replace(/^"+|"+$/g, "").trim());
    if (cols.length < 3) continue;
    const domain = extractDomain(cols[2].split(":")[0]);
    if (isValidDomain(domain)) domains.push(domain);
  }
  return domains;
}

export function parsePhishTankCsv(text: string): string[] {
  const domains: string[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("phish_id") || trimmed.startsWith("#")) continue;
    const cols = trimmed.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/);
    if (cols.length < 2) continue;
    const domain = extractDomain(cols[1].replace(/^"|"$/g, ""));
    if (isValidDomain(domain)) domains.push(domain);
  }
  return domains;
}

export function parsePhishStatsCsv(text: string): string[] {
  const domains: string[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(",date")) continue;
    const cols = trimmed.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/);
    if (cols.length < 3) continue;
    const domain = extractDomain(cols[2].replace(/^"|"$/g, ""));
    if (isValidDomain(domain)) domains.push(domain);
  }
  return domains;
}

export function parseFeed(feed: Feed, rawText: string, rawJson: unknown): string[] {
  if (feed.format === "json_threatfox") return parseThreatFox(rawJson);
  if (feed.format === "csv_threatfox") return parseThreatFoxCsv(rawText);
  if (feed.format === "csv_phishtank") return parsePhishTankCsv(rawText);
  if (feed.format === "csv_phishstats") return parsePhishStatsCsv(rawText);
  if (feed.listType === "url") return parseUrls(rawText);
  return parsePlain(rawText);
}
