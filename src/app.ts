import { loadDashboardData } from "./data/load";
import { Store } from "./data/store";
import { deriveKpis, toCsv } from "./data/derive";
import { renderHeader } from "./components/header";
import { renderKpis } from "./components/kpis";
import { renderFilters } from "./filters/filterBar";
import { createTable } from "./table/table";
import { Charts } from "./charts/charts";
import { initDetailPanel } from "./components/detailPanel";
import { renderMethodology } from "./methodology/methodology";
import { el, mount } from "./components/dom";

const THEME_KEY = "crp-theme";

function applyTheme(theme: "dark" | "light"): void {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* storage may be unavailable; theme still applies for the session */
  }
}

function initTheme(): "dark" | "light" {
  let theme: "dark" | "light" = "dark";
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") theme = saved;
  } catch {
    /* ignore */
  }
  document.documentElement.setAttribute("data-theme", theme);
  return theme;
}

function banner(kind: "fixture" | "degraded", title: string, body: string): HTMLElement {
  return el("div", { class: `banner banner--${kind}` }, [
    el("div", {}, [el("div", { class: "banner__title", text: title }), el("div", { text: body })]),
  ]);
}

export async function boot(): Promise<void> {
  const errorSlot = document.getElementById("errorSlot")!;
  initTheme();

  let data;
  try {
    data = await loadDashboardData();
  } catch (err) {
    mount(errorSlot,
      el("div", { class: "banner banner--degraded" }, [
        el("div", {}, [
          el("div", { class: "banner__title", text: "Could not load dashboard data" }),
          el("div", { text: "The prepared data files could not be fetched. If you are running locally, generate them first with: npm run data:fixture" }),
          el("div", { class: "meta-line", text: String((err as Error).message) }),
        ]),
      ]),
    );
    return;
  }

  const store = new Store(data);
  const charts = new Charts();
  const detail = initDetailPanel();
  void detail;

  // Static regions.
  const header = document.getElementById("masthead") as HTMLElement;
  const bannerSlot = document.getElementById("bannerSlot") as HTMLElement;
  const kpiRoot = document.getElementById("kpis") as HTMLElement;
  const chartsRoot = document.getElementById("charts") as HTMLElement;
  const queueRoot = document.getElementById("queue") as HTMLElement;
  const filtersRoot = document.getElementById("filters") as HTMLElement;
  const methodRoot = document.getElementById("methodology") as HTMLElement;
  const dashboardRoot = document.getElementById("dashboard") as HTMLElement;

  let currentTheme = document.documentElement.getAttribute("data-theme") as "dark" | "light";
  let methodOpen = false;

  const toggleTheme = () => {
    currentTheme = currentTheme === "dark" ? "light" : "dark";
    applyTheme(currentTheme);
    charts.refreshTheme(store.filtered());
  };

  const toggleMethodology = () => {
    methodOpen = !methodOpen;
    methodRoot.classList.toggle("hidden", !methodOpen);
    dashboardRoot.classList.toggle("hidden", methodOpen);
    if (methodOpen) {
      renderMethodology(methodRoot, store.data.methodology, store.data.status);
      methodRoot.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const refresh = async () => {
    try {
      const fresh = await loadDashboardData();
      store.data = fresh;
      renderAll();
    } catch {
      /* keep showing current data */
    }
  };

  renderHeader(header, store, {
    onToggleTheme: toggleTheme,
    onToggleMethodology: toggleMethodology,
    onRefresh: refresh,
  });

  // Banners.
  const banners: HTMLElement[] = [];
  if (store.data.status.fixture_mode) {
    banners.push(banner("fixture", "Demo dataset",
      "This site is showing bundled sample data, not a live feed. Configure the scheduled workflow to populate real data from CISA KEV, NVD and EPSS."));
  }
  if (store.data.status.overall_status !== "Current") {
    const stale = store.data.status.sources.filter((s) => !s.ok).map((s) => s.source).join(", ");
    banners.push(banner("degraded", `Data ${store.data.status.overall_status.toLowerCase()}`,
      `One or more sources did not refresh${stale ? ` (${stale})` : ""}. The last known-good data is shown; figures may be out of date.`));
  }
  mount(bannerSlot, ...banners);

  // Export.
  const onExport = () => {
    const csv = toCsv(store.filtered());
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: "cyber-risk-pulse.csv" });
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  // Filter bar renders once (keeps focus); it mutates the store.
  renderFilters(filtersRoot, store, onExport);

  const table = createTable(queueRoot, store);

  const renderAll = () => {
    const filtered = store.filtered();
    renderKpis(kpiRoot, deriveKpis(filtered, store.data.vulnerabilities, store.data.methodology.thresholds));
    charts.render(filtered);
    charts.renderPulse(filtered);
    table.render();
  };

  charts.render(store.filtered());
  void chartsRoot;
  store.subscribe(renderAll);
  renderAll();

  window.addEventListener("resize", () => charts.resize());
}
