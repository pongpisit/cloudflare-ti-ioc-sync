# cloudflare-ti-ioc-sync

A Cloudflare Worker that pulls OSINT threat-intelligence feeds and keeps two
[Cloudflare Zero Trust Gateway lists](https://developers.cloudflare.com/cloudflare-one/identity-security/gateway/lists/) in sync:

| Gateway list | Type | Feeds |
| --- | --- | --- |
| `CF-IOC-Domains` | DOMAIN | Abuse.ch ThreatFox, CERT.PL, maltrail/DShield, URLhaus domains, OISD Big, Hagezi TIF |
| `CF-IOC-URLs` | URL (path-aware) | Abuse.ch URLhaus, OpenPhish, VXVault |

Once the lists are wired into Gateway DNS/HTTP policies (`dns.fqdn in $IOC-Domains`,
`http.request.full_uri in $IOC-URLs`), your organization blocks known-bad hostnames and URLs automatically.

> **Note:** this repository was reconstructed from the deployed Worker (`ti-ioc-sync`) by
> extracting its uploaded bundle and rewriting it as clean, typed TypeScript. The live Worker
> name remains `ti-ioc-sync` (set in `wrangler.jsonc`) so deploys still target the same Worker.

## How it works

```
┌────────────┐   fetch    ┌───────────────┐   parse    ┌──────────────────────┐
│ 9 OSINT    │ ─────────▶ │ KV feed cache │ ─────────▶ │ domain / URL buckets │
│ feeds      │            │ (5 min TTL)   │            │ + whitelist + dedupe │
└────────────┘            └───────────────┘            └──────────┬───────────┘
                                                                  │ bulk check
                                                                  ▼
┌────────────────────────────┐   diff   ┌──────────────────────────────────────┐
│ Cloudflare Gateway lists   │ ◀─────── │ Cloudflare Intel API (skip domains   │
│ PATCH append/remove        │          │ CF already categorises as threats)   │
└────────────────────────────┘          └──────────────────────────────────────┘
```

- **Cron:** daily at `08:00 UTC` (`triggers.crons` in `wrangler.jsonc`)
- **Feed management:** enable/disable any of the 9 built-in feeds and add your own
  `.txt` feed URLs from the dashboard's *Feed Settings* section (or the `/api/feeds/*`
  endpoints). Custom feed URLs must be plain-text `.txt` lists — IP-literal, localhost,
  and credential-bearing URLs are rejected. Config is stored in KV (`feed_config`) and
  applies on the next sync; custom feeds are capped at 500 items, max 10 feeds
- **Fail-closed sync:** items are only *removed* from the Gateway lists when every active
  feed returned content this run, at least one feed is active, and no bucket was truncated
  by the 5,000-item cap. A feed outage, an empty response, or a fully disabled feed set
  skips removals instead of unblocking previously-synced IOCs
- **Caching:** raw feed bodies cached in KV for 48 h (well past the daily cadence) so a
  failed fetch falls back to stale data; Intel verdicts cached 6 h to spare API quota
- **Intel dedup:** new domains are checked against the Cloudflare Intel API; those already
  covered by CF's built-in threat categories are skipped, preserving the 5,000-item list budget
- **Whitelist:** high-trust domains (cloudflare.com, microsoft.com, …) are excluded from
  the domain list, and URL-bucket items on those hosts or their subdomains are excluded
  from the URL list
- **Diff-based sync:** only added/removed items are PATCHed to the Gateway lists
- **Manual list management:** add, remove, and browse individual items in both Gateway
  lists from the dashboard's *Gateway List Items* section (or the `/api/lists/items*`
  endpoints). Manually added items are stored in KV (`manual_items`) and **survive
  syncs** — they are merged ahead of feed content and protected from the removal diff.
  Feed-sourced items always return on the next sync if the feed still lists them
  (disable the feed to drop them permanently). Whitelisted domains are rejected and the
  5,000-item cap is enforced
- **Access control:** everything except `GET /` and `GET /api/status` requires the
  `ADMIN_TOKEN` Worker secret via the `X-Auth-Token` header (constant-time compared;
  fail-closed with 503 if the secret is unset). The dashboard prompts for the token once
  per browser session when you use an admin action

## HTTP API

All routes except the two public reads require an `X-Auth-Token` header matching the
`ADMIN_TOKEN` secret (🔒 below).

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/` | public | Dashboard (stats, feed health, live terminal, feed settings) |
| GET | `/api/status` | public | JSON status + active feed list |
| GET | `/api/feeds` | 🔒 | All feeds with enabled/custom state |
| POST | `/api/feeds/toggle` | 🔒 | Enable/disable a feed — body `{ "id": "oisd_big", "enabled": false }` |
| POST | `/api/feeds/custom` | 🔒 | Add a custom feed — body `{ "url": "https://…/list.txt", "listType": "domain" }`. **Only `.txt` plain-text URLs are accepted**; capped at 500 items per feed, max 10 custom feeds |
| POST | `/api/feeds/custom/remove` | 🔒 | Remove a custom feed — body `{ "id": "custom_…" }` |
| GET | `/api/lists/items?list=domain\|url` | 🔒 | All items of a Gateway list with `manual` flags |
| POST | `/api/lists/items` | 🔒 | Add items manually — body `{ "list": "domain" \| "url", "items": ["…"] }` (max 1,000; validated; whitelisted/invalid/duplicates skipped with reasons; stored in KV so they survive syncs) |
| POST | `/api/lists/items/remove` | 🔒 | Remove items — body `{ "list": …, "items": ["…"] }`; also removes them from the manual set |
| GET | `/sync/stream` | 🔒 | Live streaming log of a full sync run |
| POST | `/sync` | 🔒 | Trigger sync in background |
| POST | `/sync/run` | 🔒 | Run sync inline, returns the result JSON |
| GET | `/debug/feed?id=` | 🔒 | Probe a feed (status, line count, sample) |
| GET | `/debug/intel?domain=` | 🔒 | Intel lookup for one domain |
| GET | `/debug/list` | 🔒 | Sample of current Gateway list items |
| POST | `/bootstrap` | 🔒 | Create the `CF-IOC-Domains` list |
| POST | `/bootstrap/url` | 🔒 | Create the `CF-IOC-URLs` list |
| POST | `/reset/url-list` | 🔒 | Clear the URL list |

```sh
# Authenticated call example
curl -X POST https://<worker-host>/sync/run -H "X-Auth-Token: $ADMIN_TOKEN"
```

## Setup

```bash
npm install
cp .dev.vars.example .dev.vars   # fill in for local dev
npx wrangler kv namespace create IOC_CACHE   # then put its id in wrangler.jsonc
```

Required secrets (set with `npx wrangler secret put <NAME>`):

| Secret | Description |
| --- | --- |
| `CF_ACCOUNT_ID` | Cloudflare account ID |
| `CF_API_TOKEN` | API token with Gateway List edit + Intel read permissions |
| `CF_LIST_ID` | Gateway list ID for the DOMAIN list |
| `CF_URL_LIST_ID` | Gateway list ID for the URL list |
| `ADMIN_TOKEN` | Shared secret for every route except `GET /` and `GET /api/status` (sent as `X-Auth-Token`). Generate with `openssl rand -hex 32`. **Required** — without it, admin endpoints fail closed with 503 |

If the lists don't exist yet, `POST /bootstrap` and `POST /bootstrap/url` create them and
return the IDs.

## Commands

```bash
npm run dev         # local dev (workerd)
npm run deploy      # wrangler deploy
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm test            # vitest
npm run cf-typegen  # regenerate worker-configuration.d.ts
```

CI (`.github/workflows/ci.yml`) runs typecheck, lint, tests and `wrangler deploy --dry-run`
on every push/PR. A commented-out deploy job shows how to enable deployments from `main`.

## License

[MIT](LICENSE)
