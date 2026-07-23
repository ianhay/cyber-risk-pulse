import type { Methodology, Status, Vulnerability } from "../types";

// Files are served from the site's own /data directory. import.meta.env.BASE_URL
// resolves the GitHub Pages sub-path automatically, so the browser only ever
// requests prepared local files - never NVD directly.
const base = import.meta.env.BASE_URL.replace(/\/$/, "");

async function getJson<T>(name: string): Promise<T> {
  const res = await fetch(`${base}/data/${name}`, { cache: "no-cache" });
  if (!res.ok) {
    throw new Error(`Failed to load ${name}: HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

export interface DashboardData {
  vulnerabilities: Vulnerability[];
  status: Status;
  methodology: Methodology;
}

export async function loadDashboardData(): Promise<DashboardData> {
  const [vulnerabilities, status, methodology] = await Promise.all([
    getJson<Vulnerability[]>("current_vulnerabilities.json"),
    getJson<Status>("status.json"),
    getJson<Methodology>("methodology.json"),
  ]);
  return { vulnerabilities, status, methodology };
}
