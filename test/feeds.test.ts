import { describe, expect, it } from "vitest";
import {
  FEEDS,
  extractDomain,
  isValidDomain,
  parseFeed,
  parsePhishStatsCsv,
  parsePhishTankCsv,
  parsePlain,
  parseThreatFox,
  parseThreatFoxCsv,
  parseUrls,
} from "../src/feeds";

describe("FEEDS registry", () => {
  it("has unique ids", () => {
    const ids = FEEDS.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("contains 9 feeds with valid urls and list types", () => {
    expect(FEEDS.length).toBe(9);
    for (const f of FEEDS) {
      expect(f.url).toMatch(/^https?:\/\//);
      expect(["domain", "url"]).toContain(f.listType);
      expect(["plain", "csv_threatfox", "csv_phishtank", "csv_phishstats", "json_threatfox"]).toContain(f.format);
    }
  });
});

describe("isValidDomain", () => {
  it("accepts valid domains", () => {
    expect(isValidDomain("example.com")).toBe(true);
    expect(isValidDomain("sub.example.co.uk")).toBe(true);
    expect(isValidDomain("a-b.example.io")).toBe(true);
  });

  it("rejects invalid domains", () => {
    expect(isValidDomain("bad_domain.com")).toBe(false);
    expect(isValidDomain("-leading.com")).toBe(false);
    expect(isValidDomain("nodot")).toBe(false);
    expect(isValidDomain(`${"a".repeat(250)}.com`)).toBe(false); // >253 chars
  });
});

describe("extractDomain", () => {
  it("extracts hostname from urls", () => {
    expect(extractDomain("https://example.com/path?x=1")).toBe("example.com");
    expect(extractDomain("http://EVIL.example.NET/x")).toBe("evil.example.net");
  });

  it("strips wildcard prefix", () => {
    expect(extractDomain("*.example.com")).toBe("example.com");
  });

  it("handles bare hostnames", () => {
    expect(extractDomain("Example.COM")).toBe("example.com");
  });
});

describe("parsePlain", () => {
  it("skips comments and blank lines", () => {
    const input = [
      "# comment",
      "; another comment",
      "",
      "example.com",
      "https://plain.example.org/path",
      "not a domain!!",
    ].join("\n");
    expect(parsePlain(input)).toEqual(["example.com", "plain.example.org"]);
  });
});

describe("parseUrls", () => {
  it("normalizes urls: lowercases scheme/host, strips trailing slashes and fragments", () => {
    const input = ["HTTPS://Example.COM/Path/", "https://phish.io/login#anchor", "just some text"].join("\n");
    expect(parseUrls(input)).toEqual(["https://example.com/Path", "https://phish.io/login"]);
  });

  it("keeps query strings and ports", () => {
    expect(parseUrls("https://evil.io:8443/a?b=c")).toEqual(["https://evil.io:8443/a?b=c"]);
  });

  it("skips non-url lines", () => {
    expect(parseUrls("# header\nplaindomain.com")).toEqual([]);
  });
});

describe("parseThreatFox", () => {
  it("extracts domain iocs and skips other types", () => {
    const json = {
      data: [
        { ioc_type: "domain", ioc: "evil.com:443" },
        { ioc_type: "ip", ioc: "1.2.3.4:80" },
        { ioc_type: "domain", ioc: "phish.example.net" },
      ],
    };
    expect(parseThreatFox(json)).toEqual(["evil.com", "phish.example.net"]);
  });

  it("returns empty for missing data", () => {
    expect(parseThreatFox({})).toEqual([]);
    expect(parseThreatFox(null)).toEqual([]);
  });
});

describe("parseThreatFoxCsv", () => {
  it("parses csv rows and skips header/comments", () => {
    const csv = [
      "# ThreatFox export",
      '"first_seen_utc","ioc_id","ioc_value","ioc_type",',
      '"2024-01-01 00:00:00","x","evil.com:443","domain",',
      '"2024-01-02 00:00:00","y","c2.example.org","domain",',
    ].join("\n");
    expect(parseThreatFoxCsv(csv)).toEqual(["evil.com", "c2.example.org"]);
  });
});

describe("parsePhishTankCsv", () => {
  it("parses phish_id,url csv", () => {
    const csv = ["phish_id,url", '"12345","http://phish.example.com/login"', "# comment"].join("\n");
    expect(parsePhishTankCsv(csv)).toEqual(["phish.example.com"]);
  });
});

describe("parsePhishStatsCsv", () => {
  it("parses date,url csv taking the third column", () => {
    const csv = [",date,url", '"2024-01-01","2024-01-01 10:00","http://scam.example.net/pay"'].join("\n");
    expect(parsePhishStatsCsv(csv)).toEqual(["scam.example.net"]);
  });
});

describe("parseFeed dispatch", () => {
  it("routes plain domain feeds through parsePlain", () => {
    const feed = FEEDS.find((f) => f.id === "certpl_phishing")!;
    expect(parseFeed(feed, "good.example.com\nnot a domain", null)).toEqual(["good.example.com"]);
  });

  it("routes plain url feeds through parseUrls", () => {
    const feed = FEEDS.find((f) => f.id === "openphish_urls")!;
    expect(parseFeed(feed, "https://phish.example.org/x", null)).toEqual(["https://phish.example.org/x"]);
  });

  it("routes csv_threatfox feeds through parseThreatFoxCsv", () => {
    const feed = FEEDS.find((f) => f.id === "threatfox_domains")!;
    const csv = '"2024-01-01","x","evil.io:80","domain",';
    expect(parseFeed(feed, csv, null)).toEqual(["evil.io"]);
  });
});
