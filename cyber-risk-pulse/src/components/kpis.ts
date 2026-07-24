import type { Kpis } from "../types";
import { el, mount } from "./dom";

interface Card {
  key: keyof Kpis;
  label: string;
  def: string;
  accent?: "p1" | "warn";
  sub?: (k: Kpis) => string;
}

const CARDS: Card[] = [
  { key: "newCves", label: "New CVEs in window", def: "CVEs whose selected date falls inside the active time window and filters." },
  { key: "newKev", label: "New KEV in window", def: "CVEs added to the CISA KEV catalogue within the active filters." },
  { key: "p1", label: "Priority 1", def: "Records at the top threat-priority tier. KEV membership always maps here.", accent: "p1" },
  { key: "critical", label: "Critical severity", def: "CVSS base score at or above the critical threshold (9.0).", accent: "warn" },
  { key: "highEpss", label: "High EPSS", def: "Records whose EPSS exploitation probability meets the high threshold." },
  { key: "kevTotal", label: "KEV catalogue total", def: "All known-exploited CVEs currently in scope, ignoring filters.", sub: () => "unfiltered" },
  { key: "totalScope", label: "Total in scope", def: "Every CVE in the prepared dataset (rolling window plus all KEV).", sub: () => "unfiltered" },
];

export function renderKpis(root: HTMLElement, kpis: Kpis): void {
  mount(
    root,
    ...CARDS.map((c) =>
      el("div", { class: "kpi", "data-accent": c.accent ?? "" }, [
        el("div", { class: "kpi__label" }, [
          c.label,
          el("span", { class: "info-dot", title: c.def, "aria-label": c.def, text: "i" }),
        ]),
        el("div", { class: "kpi__value", text: String(kpis[c.key]) }),
        c.sub ? el("div", { class: "kpi__sub", text: c.sub(kpis) }) : null,
      ]),
    ),
  );
}
