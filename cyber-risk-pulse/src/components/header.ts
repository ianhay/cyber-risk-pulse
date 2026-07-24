import type { Store } from "../data/store";
import { sourceHealth } from "../data/derive";
import { el, mount } from "./dom";
import { fmtDateTime, localTime } from "./format";

interface HeaderHandlers {
  onToggleTheme: () => void;
  onToggleMethodology: () => void;
  onRefresh: () => void;
}

const SOURCE_LABELS: Record<string, string> = {
  cisa_kev: "CISA KEV",
  nvd: "NVD",
  epss: "EPSS",
};

export function renderHeader(root: HTMLElement, store: Store, h: HeaderHandlers): void {
  const { status, methodology } = store.data;

  const statusPill = el("span", { class: "status-pill", "data-status": status.overall_status }, [
    el("span", { class: "status-pill__dot" }),
    status.overall_status,
  ]);

  const controls = el("div", { class: "masthead__controls" }, [
    el("button", { class: "icon-btn", type: "button", "aria-pressed": "false", id: "themeBtn" }, ["◑ Theme"]),
    el("button", { class: "icon-btn", type: "button", id: "methodBtn" }, ["Methodology"]),
    el("button", { class: "icon-btn", type: "button", id: "refreshBtn", title: "Reload the prepared data files" }, ["↻ Refresh view"]),
  ]);

  const top = el("div", { class: "masthead__top" }, [
    el("div", { class: "brand" }, [
      el("span", { class: "brand__mark" }, [el("span", { text: "Cyber" }), "Risk Pulse"]),
      el("span", { class: "brand__sub", text: methodology.terminology.priority_sublabel }),
    ]),
    statusPill,
    controls,
  ]);

  const sourceChips = el(
    "div",
    { class: "source-strip", role: "group", "aria-label": "Source health" },
    status.sources.map((s) => {
      const { health, ageHours } = sourceHealth(status, s.source);
      const age = ageHours === null ? "" : ageHours < 1 ? "<1h" : `${Math.round(ageHours)}h`;
      return el("span", { class: "source-chip", "data-health": health, title: s.message ?? "" }, [
        el("span", { class: "source-chip__dot" }),
        SOURCE_LABELS[s.source] ?? s.source,
        el("span", { class: "source-chip__age", text: age }),
      ]);
    }),
  );

  const meta = el("div", { class: "masthead__meta" }, [
    el("span", {}, [
      "Updated ",
      el("strong", { class: "mono", text: fmtDateTime(status.generated_at) }),
      el("span", { text: ` · ${localTime(status.generated_at)} local` }),
    ]),
    sourceChips,
    el("div", { class: "pulse" }, [
      el("span", { class: "pulse__label", text: "New CVEs / day" }),
      el("div", { class: "pulse__spark", id: "pulseSpark", role: "img", "aria-label": "Sparkline of new CVEs per day" }),
    ]),
  ]);

  mount(root, top, meta);

  root.querySelector<HTMLButtonElement>("#themeBtn")!.addEventListener("click", h.onToggleTheme);
  root.querySelector<HTMLButtonElement>("#methodBtn")!.addEventListener("click", h.onToggleMethodology);
  root.querySelector<HTMLButtonElement>("#refreshBtn")!.addEventListener("click", h.onRefresh);
}
