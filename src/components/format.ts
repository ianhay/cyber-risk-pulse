import type { Vulnerability } from "../types";

export function pct(x: number | null | undefined, digits = 1): string {
  if (x === null || x === undefined) return "n/a";
  return `${(x * 100).toFixed(digits)}%`;
}

export function fmtScore(x: number | null | undefined): string {
  if (x === null || x === undefined) return "n/a";
  return x.toFixed(1);
}

export function ageDays(iso: string | null | undefined, now = Date.now()): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now - t) / 86_400_000);
}

export function fmtAge(iso: string | null | undefined): string {
  const d = ageDays(iso);
  if (d === null) return "—";
  if (d === 0) return "today";
  if (d < 30) return `${d}d`;
  if (d < 365) return `${Math.floor(d / 30)}mo`;
  return `${(d / 365).toFixed(1)}y`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toISOString().slice(0, 10);
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

export function localTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function primaryVendor(v: Vulnerability): string {
  if (v.vendors.length) return v.vendors[0];
  if (v.kev?.vendorProject) return v.kev.vendorProject;
  return "—";
}
