import type { DashboardData } from "./load";
import type { FilterState, Tier, Vulnerability } from "../types";
import { applyFilters } from "./derive";

const ALL_TIERS: Tier[] = ["P1", "P2", "P3", "P4"];

export function defaultFilters(windowDays: number): FilterState {
  return {
    windowDays,
    from: null,
    to: null,
    tiers: new Set<Tier>(),
    kevOnly: false,
    ransomwareOnly: false,
    severities: new Set<string>(),
    minEpss: null,
    minPercentile: null,
    vendor: null,
    query: "",
    basis: "published",
  };
}

type Listener = () => void;

export class Store {
  data: DashboardData;
  filters: FilterState;
  private listeners = new Set<Listener>();
  private now: number;

  constructor(data: DashboardData) {
    this.data = data;
    this.now = Date.now();
    this.filters = this.filtersFromUrl(defaultFilters(data.methodology.default_window_days));
  }

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private emit(): void {
    for (const fn of this.listeners) fn();
  }

  update(patch: Partial<FilterState>): void {
    this.filters = { ...this.filters, ...patch };
    this.syncUrl();
    this.emit();
  }

  reset(): void {
    this.filters = defaultFilters(this.data.methodology.default_window_days);
    this.syncUrl();
    this.emit();
  }

  filtered(): Vulnerability[] {
    return applyFilters(this.data.vulnerabilities, this.filters, this.now);
  }

  allVendors(): string[] {
    const set = new Set<string>();
    for (const v of this.data.vulnerabilities) for (const name of v.vendors) set.add(name);
    return [...set].sort((a, b) => a.localeCompare(b));
  }

  // --- URL persistence ---------------------------------------------------

  private syncUrl(): void {
    const f = this.filters;
    const p = new URLSearchParams();
    if (f.windowDays !== this.data.methodology.default_window_days) p.set("w", String(f.windowDays));
    if (f.from) p.set("from", f.from);
    if (f.to) p.set("to", f.to);
    if (f.tiers.size) p.set("tier", [...f.tiers].join(","));
    if (f.kevOnly) p.set("kev", "1");
    if (f.ransomwareOnly) p.set("ransom", "1");
    if (f.severities.size) p.set("sev", [...f.severities].join(","));
    if (f.minEpss !== null) p.set("epss", String(f.minEpss));
    if (f.minPercentile !== null) p.set("pct", String(f.minPercentile));
    if (f.vendor) p.set("vendor", f.vendor);
    if (f.query) p.set("q", f.query);
    if (f.basis !== "published") p.set("basis", f.basis);
    const qs = p.toString();
    const url = qs ? `?${qs}` : location.pathname;
    history.replaceState(null, "", url);
  }

  private filtersFromUrl(base: FilterState): FilterState {
    const p = new URLSearchParams(location.search);
    const f = { ...base };
    const w = p.get("w");
    if (w === "custom") f.windowDays = "custom";
    else if (w && !Number.isNaN(Number(w))) f.windowDays = Number(w);
    f.from = p.get("from");
    f.to = p.get("to");
    const tier = p.get("tier");
    if (tier) f.tiers = new Set(tier.split(",").filter((t) => ALL_TIERS.includes(t as Tier)) as Tier[]);
    f.kevOnly = p.get("kev") === "1";
    f.ransomwareOnly = p.get("ransom") === "1";
    const sev = p.get("sev");
    if (sev) f.severities = new Set(sev.split(","));
    const epss = p.get("epss");
    if (epss && !Number.isNaN(Number(epss))) f.minEpss = Number(epss);
    const pct = p.get("pct");
    if (pct && !Number.isNaN(Number(pct))) f.minPercentile = Number(pct);
    f.vendor = p.get("vendor");
    f.query = p.get("q") ?? "";
    const basis = p.get("basis");
    if (basis === "modified") f.basis = "modified";
    return f;
  }
}
