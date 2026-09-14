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

  it("escapes single quotes in rendered error strings", () => {
    const nasty: SyncResult = { ...sample, feedErrors: ["it's a 'quoted' error"] };
    const html = renderDashboard(nasty);
    expect(html).toContain("it&#39;s a &#39;quoted&#39; error");
    expect(html).not.toContain("it's a 'quoted' error</div>");
  });

  it("inline client script parses as valid JavaScript (catches template-literal escape bugs)", () => {
    const html = renderDashboard(sample);
    const match = html.match(/<script>\n([\s\S]*?)\n<\/script>/);
    expect(match).not.toBeNull();
    // new Function parses the body without executing it; any escaping mistake in the
    // template literal (e.g. \n inside a regex or string) becomes a SyntaxError here.
    expect(() => new Function(match![1])).not.toThrow();
    // The handlers referenced by inline onclick attributes must exist in the script,
    // AND so must the auth helpers those handlers call (a missing definition parses
    // fine but throws ReferenceError at click time — exactly the bug this guards).
    for (const fn of [
      "getAdminToken",
      "handleAuthError",
      "authFetch",
      "triggerSync",
      "toggleStream",
      "toggleFeed",
      "addCustomFeed",
      "removeCustomFeed",
      "switchListTab",
      "loadListItems",
      "addListItems",
      "itemsPage",
    ]) {
      expect(match![1]).toContain(`function ${fn}`);
    }
  });

  it("shows the actual daily cron schedule", () => {
    const html = renderDashboard(sample);
    expect(html).toContain("08:00 UTC");
    expect(html).not.toContain("every 15 min");
  });
});

describe("renderDashboard feed settings", () => {
  it("renders a settings section with all built-in feeds", () => {
    const html = renderDashboard(sample);
    expect(html).toContain("Feed Settings");
    expect(html).toContain('toggleFeed(this, \'urlhaus_urls\')');
    expect(html).toContain('toggleFeed(this, \'hagezi_threat\')');
  });

  it("reflects disabled feeds via unchecked boxes", () => {
    const html = renderDashboard(sample, { disabled: ["oisd_big"], custom: [] });
    const checkboxArea = html.slice(html.indexOf("Feed Settings"), html.indexOf('id="custom-url"'));
    const checked = (checkboxArea.match(/type="checkbox" checked/g) ?? []).length;
    const total = (checkboxArea.match(/type="checkbox"/g) ?? []).length;
    expect(total).toBe(9);
    expect(checked).toBe(8);
  });

  it("renders custom feeds with remove buttons", () => {
    const html = renderDashboard(sample, {
      disabled: [],
      custom: [
        {
          id: "custom_abc",
          name: "example.com (custom .txt)",
          url: "https://example.com/list.txt",
          format: "plain",
          listType: "domain",
          maxDomains: 500,
        },
      ],
    });
    expect(html).toContain("custom_abc");
    expect(html).toContain("removeCustomFeed('custom_abc')");
    expect(html).toContain("custom-tag");
  });

  it("shows the .txt-only hint", () => {
    const html = renderDashboard(sample);
    expect(html).toContain("Only <b>.txt</b> plain-text lists are accepted");
  });
});
