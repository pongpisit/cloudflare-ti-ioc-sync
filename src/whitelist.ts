/**
 * High-trust domains that must never be blocked by feed-driven or manually managed
 * list content. For domain-bucket items the check is exact-match; for URL-bucket
 * items the check applies to the URL's hostname, including subdomains.
 */
export const WHITELIST = new Set([
  "cloudflare.com",
  "microsoft.com",
  "windows.com",
  "office.com",
  "google.com",
  "apple.com",
  "akamai.net",
  "fastly.net",
]);

export function isWhitelistedUrl(u: string): boolean {
  try {
    const host = new URL(u).hostname.toLowerCase();
    for (const d of WHITELIST) {
      if (host === d || host.endsWith(`.${d}`)) return true;
    }
  } catch {
    // Not a parseable URL — let the existing diff handling deal with it.
  }
  return false;
}
