import type { Store } from "../data/store";
import type { Tier } from "../types";
import { el, mount } from "../components/dom";

const TIERS: Tier[] = ["P1", "P2", "P3", "P4"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const SEV_LABEL: Record<string, string> = {
  CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", UNKNOWN: "Unknown",
};

export function renderFilters(root: HTMLElement, store: Store, onExport: () => void): void {
  const f = store.filters;
  const windows = store.data.methodology.time_windows_days;

  // Window segmented control.
  const windowSeg = el("div", { class: "seg", role: "group", "aria-label": "Time window" },
    [...windows.map((d) =>
      el("button", { type: "button", "data-w": d, "aria-pressed": String(f.windowDays === d) }, [`${d}d`]),
    ), el("button", { type: "button", "data-w": "custom", "aria-pressed": String(f.windowDays === "custom") }, ["Custom"])],
  );
  windowSeg.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest("button");
    if (!btn) return;
    const w = btn.dataset.w!;
    store.update({ windowDays: w === "custom" ? "custom" : Number(w) });
    windowSeg.querySelectorAll("button").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.w === w)));
    customWrap.classList.toggle("hidden", w !== "custom");
  });

  const fromInput = el("input", { type: "date", value: f.from ?? "", "aria-label": "From date" });
  const toInput = el("input", { type: "date", value: f.to ?? "", "aria-label": "To date" });
  fromInput.addEventListener("change", () => store.update({ from: fromInput.value || null }));
  toInput.addEventListener("change", () => store.update({ to: toInput.value || null }));
  const customWrap = el("div", { class: `field ${f.windowDays === "custom" ? "" : "hidden"}` }, [
    el("span", { class: "field__label", text: "Custom range" }),
    el("div", { style: "display:flex;gap:6px", }, [fromInput, toInput]),
  ]);

  // Basis segmented.
  const basisSeg = el("div", { class: "seg", role: "group", "aria-label": "Date basis" }, [
    el("button", { type: "button", "data-b": "published", "aria-pressed": String(f.basis === "published") }, ["Published"]),
    el("button", { type: "button", "data-b": "modified", "aria-pressed": String(f.basis === "modified") }, ["Modified"]),
  ]);
  basisSeg.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest("button");
    if (!btn) return;
    const b = btn.dataset.b as "published" | "modified";
    store.update({ basis: b });
    basisSeg.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.b === b)));
  });

  // Tier toggles.
  const tierGroup = el("div", { class: "toggle-group", role: "group", "aria-label": "Priority tier" },
    TIERS.map((t) =>
      el("button", { class: "chip-toggle", type: "button", "data-tier": t, "aria-pressed": String(f.tiers.has(t)) }, [
        el("span", { class: "chip-toggle__swatch", style: `background:var(--${t.toLowerCase()})` }),
        t,
      ]),
    ),
  );
  tierGroup.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest("button");
    if (!btn) return;
    const t = btn.dataset.tier as Tier;
    const next = new Set(store.filters.tiers);
    next.has(t) ? next.delete(t) : next.add(t);
    store.update({ tiers: next });
    btn.setAttribute("aria-pressed", String(next.has(t)));
  });

  // Severity toggles.
  const sevGroup = el("div", { class: "toggle-group", role: "group", "aria-label": "CVSS severity" },
    SEVERITIES.map((s) =>
      el("button", { class: "chip-toggle", type: "button", "data-sev": s, "aria-pressed": String(f.severities.has(s)) }, [
        el("span", { class: `chip-toggle__swatch sev-${s}` }),
        SEV_LABEL[s],
      ]),
    ),
  );
  sevGroup.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest("button");
    if (!btn) return;
    const s = btn.dataset.sev!;
    const next = new Set(store.filters.severities);
    next.has(s) ? next.delete(s) : next.add(s);
    store.update({ severities: next });
    btn.setAttribute("aria-pressed", String(next.has(s)));
  });

  // KEV / ransomware toggles.
  const kevBtn = el("button", { class: "chip-toggle", type: "button", "aria-pressed": String(f.kevOnly) }, [
    el("span", { class: "chip-toggle__swatch", style: "background:var(--p1)" }), "KEV only",
  ]);
  kevBtn.addEventListener("click", () => {
    const v = !store.filters.kevOnly;
    store.update({ kevOnly: v });
    kevBtn.setAttribute("aria-pressed", String(v));
  });
  const ransomBtn = el("button", { class: "chip-toggle", type: "button", "aria-pressed": String(f.ransomwareOnly) }, [
    el("span", { class: "chip-toggle__swatch", style: "background:var(--ransomware)" }), "Ransomware",
  ]);
  ransomBtn.addEventListener("click", () => {
    const v = !store.filters.ransomwareOnly;
    store.update({ ransomwareOnly: v });
    ransomBtn.setAttribute("aria-pressed", String(v));
  });

  // EPSS numeric fields.
  const epssInput = el("input", { type: "number", min: "0", max: "1", step: "0.05", value: f.minEpss ?? "", placeholder: "0.00" });
  epssInput.addEventListener("change", () =>
    store.update({ minEpss: epssInput.value === "" ? null : clamp01(Number(epssInput.value)) }));
  const pctInput = el("input", { type: "number", min: "0", max: "1", step: "0.01", value: f.minPercentile ?? "", placeholder: "0.00" });
  pctInput.addEventListener("change", () =>
    store.update({ minPercentile: pctInput.value === "" ? null : clamp01(Number(pctInput.value)) }));

  // Vendor select.
  const vendorSel = el("select", { "aria-label": "Vendor" }, [
    el("option", { value: "", text: "All vendors" }),
    ...store.allVendors().map((v) => el("option", { value: v, text: v, selected: f.vendor === v })),
  ]);
  vendorSel.addEventListener("change", () => store.update({ vendor: vendorSel.value || null }));

  // Search.
  const search = el("input", { type: "search", value: f.query, placeholder: "CVE ID, vendor, keyword…", "aria-label": "Search" });
  let t: number | undefined;
  search.addEventListener("input", () => {
    window.clearTimeout(t);
    t = window.setTimeout(() => store.update({ query: search.value }), 150);
  });

  const count = el("span", { class: "filters__count", id: "resultCount" });
  const resetBtn = el("button", { class: "btn-reset", type: "button", text: "Reset filters" });
  resetBtn.addEventListener("click", () => location.assign(location.pathname));
  const exportBtn = el("button", { class: "btn-primary", type: "button", text: "Export CSV" });
  exportBtn.addEventListener("click", onExport);

  const field = (label: string, control: Node) =>
    el("div", { class: "field" }, [el("span", { class: "field__label", text: label }), control]);

  mount(root,
    el("div", { class: "filters__row" }, [
      field("Window", windowSeg),
      customWrap,
      field("Date basis", basisSeg),
      field("Priority", tierGroup),
      field("Severity", sevGroup),
    ]),
    el("div", { class: "filters__row" }, [
      field("Flags", el("div", { class: "toggle-group" }, [kevBtn, ransomBtn])),
      field("Min EPSS prob.", epssInput),
      field("Min percentile", pctInput),
      field("Vendor", vendorSel),
      field("Search", search),
    ]),
    el("div", { class: "filters__foot" }, [count, resetBtn, exportBtn]),
  );

  const updateCount = () => {
    const n = store.filtered().length;
    const total = store.data.vulnerabilities.length;
    mount(count, el("strong", { text: String(n) }), ` of ${total} records match`);
  };
  updateCount();
  store.subscribe(updateCount);
}

function clamp01(x: number): number {
  if (Number.isNaN(x)) return 0;
  return Math.min(1, Math.max(0, x));
}
