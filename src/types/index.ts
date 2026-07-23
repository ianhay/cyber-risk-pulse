// Types mirroring the compact JSON produced by the Python ingestion.
// These match schemas/vulnerability.schema.json and the *.json outputs.

export type Tier = "P1" | "P2" | "P3" | "P4";

export interface Cvss {
  version: string;
  score: number | null;
  severity: string | null;
  vector: string | null;
  source: string | null;
}

export interface Epss {
  p: number | null;
  pct: number | null;
  date: string | null;
}

export interface Kev {
  isKev: true;
  vendorProject: string | null;
  product: string | null;
  name: string | null;
  dateAdded: string | null;
  dueDate: string | null;
  requiredAction: string | null;
  ransomware: string | null;
}

export interface Reference {
  url: string;
  source: string | null;
}

export interface Vulnerability {
  id: string;
  desc: string;
  published: string | null;
  modified: string | null;
  status: string | null;
  vendors: string[];
  vendorsRaw: string[];
  products: string[];
  cwes: string[];
  cvss: Cvss | null;
  epss: Epss | null;
  kev: Kev | null;
  tier: Tier;
  reasons: string[];
  refs: Reference[];
  flags: string[];
}

export interface SourceStatus {
  source: string;
  ok: boolean;
  record_count: number;
  fetched_at: string | null;
  used_last_known_good: boolean;
  message: string | null;
}

export interface Status {
  overall_status: "Current" | "Degraded" | "Stale";
  generated_at: string;
  app_version: string;
  build_commit: string | null;
  fixture_mode: boolean;
  freshness: Record<string, number>;
  sources: SourceStatus[];
}

export interface Methodology {
  terminology: { priority_label: string; priority_sublabel: string; index_label: string };
  statement: string;
  priority_rules: Record<string, unknown>;
  tier_labels: Record<string, string>;
  thresholds: Record<string, number>;
  time_windows_days: number[];
  default_window_days: number;
  sources: Record<string, { name: string }>;
}

export type DateBasis = "published" | "modified";

export interface FilterState {
  windowDays: number | "custom";
  from: string | null;
  to: string | null;
  tiers: Set<Tier>;
  kevOnly: boolean;
  ransomwareOnly: boolean;
  severities: Set<string>;
  minEpss: number | null;
  minPercentile: number | null;
  vendor: string | null;
  query: string;
  basis: DateBasis;
}

export interface Kpis {
  newCves: number;
  newKev: number;
  kevTotal: number;
  highEpss: number;
  critical: number;
  p1: number;
  totalScope: number;
}
