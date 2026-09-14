import { describe, expect, it } from "vitest";
import { renderDashboard } from "../src/dashboard";
import type { SyncResult } from "../src/types";

const sample: SyncResult = {
  ts: "2026-09-14T08:00:00.000Z",
  elapsedMs: 12_345,
  feedStats: { urlhaus_urls: 100, threatfox_domains: 50 },
  feedErrors: [],
  domains: { fresh: 50, intelSkipped: 5, current: 45, added: 10, removed: 5, total: 50 },
  urls: { fresh: 100, current: 95, added: 20, removed: 15, total: 100 },
};

describe("renderDashboard", () => {
  it("renders empty state when never synced", () => {
    const html = renderDashboard(null);
    expect(html).toContain("Never");
    expect(html).toContain("No data yet");
  });

  it("renders stats and feed rows", () => {
    const html = renderDashboard(sample);
    expect(html).toContain("50");
    expect(html).toContain("Abuse.ch URLhaus");
    expect(html).toContain("badge-url");
    expect(html).toContain("badge-domain");
  });

  it("HTML-escapes feed error strings to prevent XSS", () => {
    const malicious: SyncResult = {
      ...sample,
      feedErrors: ['urlhaus_urls: <script>alert("xss")</script> & more'],
    };
    const html = renderDashboard(malicious);
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;");
  });

  it("shows the actual daily cron schedule", () => {
    const html = renderDashboard(sample);
    expect(html).toContain("08:00 UTC");
    expect(html).not.toContain("every 15 min");
  });
});
