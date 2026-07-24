import type {
  DateBasis,
  FilterState,
  Kpis,
  Status,
  Tier,
  Vulnerability,
} from "../types";

const DAY_MS = 86_400_000;

function severityBucket(v: Vulnerability): string {
  const s = v.cvss?.score;
  if (s === null || s === undefined) return "UNKNOWN";
  if (s >= 9) return "CRITICAL";
  if (s >= 7) return "HIGH";
  if (s >= 4) return "MEDIUM";
  if (s > 0) return "LOW";
  return "NONE";
}

function basisDate(v: Vulnerability, basis: DateBasis): number | null {
  const raw = basis === "modified" ? v.modified : v.published;
  if (!raw) return null;
  const t = Date.parse(raw);
  return Number.isNaN(t) ? null : t;
}

/** Apply every active filter. Order does not matter; all views call this. */
export function applyFilters(
  records: Vulnerability[],
  f: FilterState,
  now: number = Date.now(),
): Vulnerability[] {
  let fromMs: number | null = null;
  let toMs: number | null = null;
  if (f.windowDays === "custom") {
    fromMs = f.from ? Date.parse(f.from) : null;
    toMs = f.to ? Date.parse(f.to) + DAY_MS : null;
  } else {
    fromMs = now - f.windowDays * DAY_MS;
  }

  const q = f.query.trim().toLowerCase();

  return records.filter((v) => {
    const d = basisDate(v, f.basis);
    // KEV-only records may lack a date; keep them when KEV is relevant.
    if (fromMs !== null || toMs !== null) {
      if (d === null) {
        if (!v.kev) return false;
      } else {
        if (fromMs !== null && d < fromMs) return false;
        if (toMs !== null && d > toMs) return false;
      }
    }
    if (f.tiers.size && !f.tiers.has(v.tier)) return false;
    if (f.kevOnly && !v.kev) return false;
    if (f.ransomwareOnly && (v.kev?.ransomware ?? "").toLowerCase() !== "known") return false;
    if (f.severities.size && !f.severities.has(severityBucket(v))) return false;
    if (f.minEpss !== null) {
      if (v.epss?.p == null || v.epss.p < f.minEpss) return false;
    }
    if (f.minPercentile !== null) {
      if (v.epss?.pct == null || v.epss.pct < f.minPercentile) return false;
    }
    if (f.vendor && !v.vendors.includes(f.vendor)) return false;
    if (q) {
      const hay = `${v.id} ${v.desc} ${v.vendors.join(" ")} ${v.products.join(" ")}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

export function deriveKpis(
  filtered: Vulnerability[],
  allRecords: Vulnerability[],
  thresholds: Record<string, number>,
): Kpis {
  const highEpssT = thresholds.high_epss_probability ?? 0.1;
  const critT = thresholds.critical_cvss ?? 9;
  return {
    newCves: filtered.length,
    newKev: filtered.filter((v) => v.kev).length,
    kevTotal: allRecords.filter((v) => v.kev).length,
    highEpss: filtered.filter((v) => (v.epss?.p ?? -1) >= highEpssT).length,
    critical: filtered.filter((v) => (v.cvss?.score ?? -1) >= critT).length,
    p1: filtered.filter((v) => v.tier === "P1").length,
    totalScope: allRecords.length,
  };
}

export function tierCounts(records: Vulnerability[]): Record<Tier, number> {
  const c: Record<Tier, number> = { P1: 0, P2: 0, P3: 0, P4: 0 };
  for (const v of records) c[v.tier]++;
  return c;
}

export function severityCounts(records: Vulnerability[]): Record<string, number> {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const c: Record<string, number> = {};
  for (const k of order) c[k] = 0;
  for (const v of records) c[severityBucket(v)]++;
  return c;
}

/** EPSS probability histogram in 10 buckets of 10 percentage points. */
export function epssHistogram(records: Vulnerability[]): number[] {
  const buckets = new Array(10).fill(0);
  for (const v of records) {
    if (v.epss?.p == null) continue;
    const idx = Math.min(9, Math.floor(v.epss.p * 10));
    buckets[idx]++;
  }
  return buckets;
}

export function seriesByDay(
  records: Vulnerability[],
  pick: (v: Vulnerability) => string | null,
): { dates: string[]; counts: number[] } {
  const map = new Map<string, number>();
  for (const v of records) {
    const raw = pick(v);
    if (!raw) continue;
    const day = raw.slice(0, 10);
    map.set(day, (map.get(day) ?? 0) + 1);
  }
  const dates = [...map.keys()].sort();
  return { dates, counts: dates.map((d) => map.get(d)!) };
}

export function topVendors(
  records: Vulnerability[],
  limit = 10,
): { vendor: string; count: number }[] {
  const c = new Map<string, number>();
  for (const v of records) {
    for (const vendor of new Set(v.vendors)) {
      c.set(vendor, (c.get(vendor) ?? 0) + 1);
    }
  }
  return [...c.entries()]
    .map(([vendor, count]) => ({ vendor, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function timeToKev(records: Vulnerability[]): { cve: string; days: number }[] {
  const out: { cve: string; days: number }[] = [];
  for (const v of records) {
    if (!v.kev?.dateAdded || !v.published) continue;
    const added = Date.parse(v.kev.dateAdded.slice(0, 10));
    const pub = Date.parse(v.published.slice(0, 10));
    if (Number.isNaN(added) || Number.isNaN(pub)) continue;
    const days = Math.round((added - pub) / DAY_MS);
    if (days >= 0) out.push({ cve: v.id, days });
  }
  return out.sort((a, b) => a.days - b.days);
}

const TIER_RANK: Record<Tier, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

export type SortKey = "priority" | "epss" | "cvss" | "published" | "cve";

export function sortRecords(
  records: Vulnerability[],
  key: SortKey,
  dir: "asc" | "desc",
): Vulnerability[] {
  const sign = dir === "asc" ? 1 : -1;
  const val = (v: Vulnerability): number | string => {
    switch (key) {
      case "priority":
        return TIER_RANK[v.tier];
      case "epss":
        return v.epss?.p ?? -1;
      case "cvss":
        return v.cvss?.score ?? -1;
      case "published":
        return v.published ? Date.parse(v.published) : -1;
      case "cve":
        return v.id;
    }
  };
  return [...records].sort((a, b) => {
    const av = val(a);
    const bv = val(b);
    if (av < bv) return -1 * sign;
    if (av > bv) return 1 * sign;
    return 0;
  });
}

/** Build a CSV string for the given (already filtered) records. */
export function toCsv(records: Vulnerability[]): string {
  const headers = [
    "cve_id", "tier", "kev", "ransomware", "cvss_version", "cvss_score",
    "cvss_severity", "epss_probability", "epss_percentile", "published",
    "vendors", "products", "description",
  ];
  const esc = (s: unknown): string => {
    const str = s === null || s === undefined ? "" : String(s);
    return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
  };
  const rows = records.map((v) =>
    [
      v.id,
      v.tier,
      v.kev ? "yes" : "no",
      v.kev?.ransomware ?? "",
      v.cvss?.version ?? "",
      v.cvss?.score ?? "",
      v.cvss?.severity ?? "",
      v.epss?.p ?? "",
      v.epss?.pct ?? "",
      v.published ?? "",
      v.vendors.join("; "),
      v.products.join("; "),
      v.desc,
    ]
      .map(esc)
      .join(","),
  );
  return [headers.join(","), ...rows].join("\n");
}

export type Health = "ok" | "warn" | "stale";

/** Source freshness given the run's generated_at and per-source thresholds. */
export function sourceHealth(status: Status, source: string, now = Date.now()): {
  health: Health;
  ageHours: number | null;
} {
  const s = status.sources.find((x) => x.source === source);
  if (!s || !s.ok) return { health: "stale", ageHours: null };
  const ref = s.fetched_at ?? status.generated_at;
  const t = Date.parse(ref);
  if (Number.isNaN(t)) return { health: "warn", ageHours: null };
  const ageHours = (now - t) / 3_600_000;
  const warn = status.freshness[`${source}_warn_hours`] ?? 36;
  const max = status.freshness[`${source}_max_hours`] ?? 96;
  if (ageHours > max) return { health: "stale", ageHours };
  if (ageHours > warn) return { health: "warn", ageHours };
  return { health: "ok", ageHours };
}
