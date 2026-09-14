export interface Env {
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  CF_LIST_ID: string;
  CF_URL_LIST_ID: string;
  IOC_CACHE: KVNamespace;
}

export type FeedFormat =
  | "plain"
  | "csv_threatfox"
  | "csv_phishtank"
  | "csv_phishstats"
  | "json_threatfox";

export type FeedListType = "domain" | "url";

export interface Feed {
  id: string;
  name: string;
  url: string;
  format: FeedFormat;
  listType: FeedListType;
  maxDomains?: number;
}

export interface FetchFeedResult {
  feedId: string;
  items: string[];
  listType: FeedListType;
  error?: string;
}

export interface FeedConfig {
  disabled: string[];
  custom: Feed[];
}

export interface SyncResult {
  ts: string;
  elapsedMs: number;
  feedStats: Record<string, number>;
  feedErrors: string[];
  domains: {
    fresh: number;
    intelSkipped: number;
    current: number;
    added: number;
    removed: number;
    total: number;
  };
  urls: {
    fresh: number;
    current: number;
    added: number;
    removed: number;
    total: number;
  };
}

export type SyncLogger = (line: string) => void;

export interface CfApiEnvelope<T> {
  success: boolean;
  result: T | null;
  errors: unknown[];
  result_info?: { total_count?: number };
}

export interface CfListItem {
  value: string;
}

export interface CfIntelDomainInfo {
  domain: string;
  risk_types?: { id: number }[];
  content_categories?: { id: number }[];
}

export interface IntelFilterResult {
  kept: string[];
  skipped: string[];
  errors: string[];
  skippedDetails: { domain: string; riskTypeIds: string }[];
}
