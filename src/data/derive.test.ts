import { describe, expect, it } from "vitest";
import {
  applyFilters,
  deriveKpis,
  epssHistogram,
  sortRecords,
  sourceHealth,
  tierCounts,
  toCsv,
} from "./derive";
import { defaultFilters } from "./store";
import type { Status, Vulnerability } from "../types";

function vuln(p: Partial<Vulnerability>): Vulnerability {
  return {
    id: "CVE-2026-0001",
    desc: "test",
    published: "2026-07-20T00:00:00Z",
    modified: "2026-07-21T00:00:00Z",
    status: "Analyzed",
    vendors: [],
    vendorsRaw: [],
    products: [],
    cwes: [],
    cvss: null,
    epss: null,
    kev: null,
    tier: "P4",
    reasons: [],
    refs: [],
    flags: [],
    ...p,
  };
}

const NOW = Date.parse("2026-07-23T00:00:00Z");

describe("applyFilters", () => {
  const records = [
    vuln({ id: "CVE-2026-0001", tier: "P1", kev: { isKev: true, vendorProject: "MS", product: "x", name: "n", dateAdded: "2026-07-22", dueDate: null, requiredAction: null, ransomware: "Known" }, vendors: ["Microsoft"], cvss: { version: "3.1", score: 9.8, severity: "CRITICAL", vector: null, source: null }, epss: { p: 0.9, pct: 0.99, date: "2026-07-23" } }),
    vuln({ id: "CVE-2026-0002", tier: "P3", vendors: ["Cisco"], cvss: { version: "3.1", score: 7.5, severity: "HIGH", vector: null, source: null }, epss: { p: 0.02, pct: 0.4, date: "2026-07-23" } }),
    vuln({ id: "CVE-2026-0003", tier: "P4", published: "2026-01-01T00:00:00Z", vendors: ["Adobe"] }),
  ];

  it("filters by time window", () => {
    const f = { ...defaultFilters(30), windowDays: 30 as const };
    const out = applyFilters(records, f, NOW);
    expect(out.map((v) => v.id)).toContain("CVE-2026-0001");
    expect(out.map((v) => v.id)).not.toContain("CVE-2026-0003"); // too old
  });

  it("keeps a KEV-only record that has no date (cannot be windowed)", () => {
    const kevNoDate = vuln({ id: "CVE-2020-0001", published: null, modified: null, kev: { isKev: true, vendorProject: "x", product: "y", name: "z", dateAdded: "2020-02-01", dueDate: null, requiredAction: null, ransomware: null } });
    const f = { ...defaultFilters(30), windowDays: 30 as const };
    expect(applyFilters([kevNoDate], f, NOW)).toHaveLength(1);
  });

  it("windows a dated KEV record like any other; a wide window brings it back", () => {
    const kevOld = vuln({ id: "CVE-2020-0002", published: "2020-01-01T00:00:00Z", kev: { isKev: true, vendorProject: "x", product: "y", name: "z", dateAdded: "2020-02-01", dueDate: null, requiredAction: null, ransomware: null } });
    const narrow = { ...defaultFilters(30), windowDays: 30 as const };
    expect(applyFilters([kevOld], narrow, NOW)).toHaveLength(0);
    const wide = { ...defaultFilters(30), windowDays: "custom" as const, from: "2019-01-01", to: "2026-12-31" };
    expect(applyFilters([kevOld], wide, NOW)).toHaveLength(1);
  });

  it("filters by tier, kev, ransomware and vendor consistently", () => {
    const f = { ...defaultFilters(365), windowDays: 365 as const, kevOnly: true };
    expect(applyFilters(records, f, NOW).every((v) => v.kev)).toBe(true);
    const f2 = { ...defaultFilters(365), windowDays: 365 as const, ransomwareOnly: true };
    expect(applyFilters(records, f2, NOW).every((v) => v.kev?.ransomware === "Known")).toBe(true);
    const f3 = { ...defaultFilters(365), windowDays: 365 as const, vendor: "Cisco" };
    expect(applyFilters(records, f3, NOW).map((v) => v.id)).toEqual(["CVE-2026-0002"]);
  });

  it("filters by minimum EPSS without treating missing as zero", () => {
    const f = { ...defaultFilters(365), windowDays: 365 as const, minEpss: 0.5 };
    const out = applyFilters(records, f, NOW);
    expect(out.map((v) => v.id)).toEqual(["CVE-2026-0001"]);
    // The record with no EPSS must be excluded, not included as 0.
    expect(out.map((v) => v.id)).not.toContain("CVE-2026-0003");
  });

  it("search matches id and vendor", () => {
    const f = { ...defaultFilters(365), windowDays: 365 as const, query: "cisco" };
    expect(applyFilters(records, f, NOW).map((v) => v.id)).toEqual(["CVE-2026-0002"]);
  });

  it("KPIs agree with the filtered set", () => {
    const f = { ...defaultFilters(365), windowDays: 365 as const };
    const filtered = applyFilters(records, f, NOW);
    const kpis = deriveKpis(filtered, records, { high_epss_probability: 0.1, critical_cvss: 9 });
    expect(kpis.newCves).toBe(filtered.length);
    expect(kpis.p1).toBe(filtered.filter((v) => v.tier === "P1").length);
    expect(kpis.critical).toBe(1); // only 0001 has CVSS >= 9
    expect(kpis.kevTotal).toBe(1); // unfiltered KEV count
  });
});

describe("aggregates", () => {
  const records = [
    vuln({ tier: "P1" }), vuln({ tier: "P1" }), vuln({ tier: "P3" }),
    vuln({ epss: { p: 0.05, pct: 0.5, date: "x" } }),
    vuln({ epss: { p: 0.95, pct: 0.99, date: "x" } }),
  ];

  it("counts tiers", () => {
    const c = tierCounts(records);
    expect(c.P1).toBe(2);
    expect(c.P3).toBe(1);
  });

  it("buckets EPSS into ten bins", () => {
    const h = epssHistogram(records);
    expect(h).toHaveLength(10);
    expect(h[0]).toBe(1); // 0.05 -> bin 0
    expect(h[9]).toBe(1); // 0.95 -> bin 9
  });
});

describe("sortRecords", () => {
  const records = [
    vuln({ id: "CVE-2026-0001", tier: "P3", cvss: { version: "3.1", score: 7, severity: "HIGH", vector: null, source: null } }),
    vuln({ id: "CVE-2026-0002", tier: "P1", cvss: { version: "3.1", score: 9, severity: "CRITICAL", vector: null, source: null } }),
  ];

  it("orders by priority ascending (P1 first)", () => {
    const out = sortRecords(records, "priority", "asc");
    expect(out[0].tier).toBe("P1");
  });

  it("orders by CVSS descending", () => {
    const out = sortRecords(records, "cvss", "desc");
    expect(out[0].cvss?.score).toBe(9);
  });
});

describe("toCsv", () => {
  it("emits a header and escapes commas", () => {
    const csv = toCsv([vuln({ id: "CVE-2026-0001", desc: "a, b, c", tier: "P1" })]);
    const [header, row] = csv.split("\n");
    expect(header.startsWith("cve_id,tier")).toBe(true);
    expect(row).toContain('"a, b, c"');
  });
});

describe("sourceHealth", () => {
  const status: Status = {
    overall_status: "Current",
    generated_at: "2026-07-23T00:00:00Z",
    app_version: "0.1.0",
    build_commit: null,
    fixture_mode: true,
    freshness: { nvd_warn_hours: 36, nvd_max_hours: 96 },
    sources: [
      { source: "nvd", ok: true, record_count: 10, fetched_at: "2026-07-23T00:00:00Z", used_last_known_good: false, message: null },
      { source: "epss", ok: false, record_count: 0, fetched_at: null, used_last_known_good: true, message: "boom" },
    ],
  };

  it("reports ok for a fresh source", () => {
    expect(sourceHealth(status, "nvd", NOW).health).toBe("ok");
  });

  it("reports stale for a failed source", () => {
    expect(sourceHealth(status, "epss", NOW).health).toBe("stale");
  });
});
