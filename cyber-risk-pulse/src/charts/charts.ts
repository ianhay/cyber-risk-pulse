import * as echarts from "echarts";
import type { Tier, Vulnerability } from "../types";
import {
  epssHistogram,
  seriesByDay,
  severityCounts,
  tierCounts,
  timeToKev,
  topVendors,
} from "../data/derive";

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

const TIER_KEYS: Tier[] = ["P1", "P2", "P3", "P4"];

function baseGrid() {
  return { left: 44, right: 16, top: 24, bottom: 28 };
}

function axisStyle() {
  const line = cssVar("--border");
  const label = cssVar("--muted");
  return {
    axisLine: { lineStyle: { color: line } },
    axisTick: { show: false },
    axisLabel: { color: label, fontSize: 11 },
    splitLine: { lineStyle: { color: line, opacity: 0.4 } },
  };
}

function tooltipStyle() {
  return {
    backgroundColor: cssVar("--surface-2"),
    borderColor: cssVar("--border-strong"),
    textStyle: { color: cssVar("--text"), fontSize: 12 },
  };
}

export class Charts {
  private instances = new Map<string, echarts.ECharts>();
  private pulse: echarts.ECharts | null = null;

  private inst(id: string): echarts.ECharts | null {
    const node = document.getElementById(id);
    if (!node) return null;
    let chart = this.instances.get(id);
    if (!chart) {
      chart = echarts.init(node, undefined, { renderer: "canvas" });
      this.instances.set(id, chart);
    }
    return chart;
  }

  render(records: Vulnerability[]): void {
    this.renderTrend(records);
    this.renderTiers(records);
    this.renderSeverity(records);
    this.renderEpss(records);
    this.renderVendors(records);
    this.renderTimeToKev(records);
  }

  private renderTrend(records: Vulnerability[]): void {
    const chart = this.inst("chartTrend");
    if (!chart) return;
    const cve = seriesByDay(records, (v) => v.published);
    const kev = seriesByDay(records.filter((v) => v.kev), (v) => v.kev?.dateAdded ?? null);
    const accent = cssVar("--accent");
    const p1 = cssVar("--p1");
    chart.setOption({
      grid: baseGrid(),
      tooltip: { trigger: "axis", ...tooltipStyle() },
      legend: { data: ["New CVEs", "KEV additions"], textStyle: { color: cssVar("--muted") }, right: 0, top: 0 },
      xAxis: { type: "category", data: cve.dates, ...axisStyle() },
      yAxis: { type: "value", minInterval: 1, ...axisStyle() },
      series: [
        { name: "New CVEs", type: "line", smooth: true, showSymbol: false, data: cve.counts,
          lineStyle: { color: accent, width: 2 }, areaStyle: { color: cssVar("--accent-soft") } },
        { name: "KEV additions", type: "bar", data: kev.dates.map((d, i) => [d, kev.counts[i]]),
          itemStyle: { color: p1 }, barMaxWidth: 14 },
      ],
    });
  }

  private renderTiers(records: Vulnerability[]): void {
    const chart = this.inst("chartTiers");
    if (!chart) return;
    const counts = tierCounts(records);
    chart.setOption({
      grid: baseGrid(),
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle() },
      xAxis: { type: "category", data: TIER_KEYS, ...axisStyle() },
      yAxis: { type: "value", minInterval: 1, ...axisStyle() },
      series: [{
        type: "bar",
        data: TIER_KEYS.map((t) => ({ value: counts[t], itemStyle: { color: cssVar(`--${t.toLowerCase()}`) } })),
        barMaxWidth: 48,
        label: { show: true, position: "top", color: cssVar("--muted") },
      }],
    });
  }

  private renderSeverity(records: Vulnerability[]): void {
    const chart = this.inst("chartSeverity");
    if (!chart) return;
    const counts = severityCounts(records);
    const keys = Object.keys(counts);
    const colorFor: Record<string, string> = {
      CRITICAL: "--sev-critical", HIGH: "--sev-high", MEDIUM: "--sev-medium",
      LOW: "--sev-low", UNKNOWN: "--sev-unknown",
    };
    chart.setOption({
      grid: baseGrid(),
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle() },
      xAxis: { type: "category", data: keys.map((k) => k[0] + k.slice(1).toLowerCase()), ...axisStyle() },
      yAxis: { type: "value", minInterval: 1, ...axisStyle() },
      series: [{
        type: "bar",
        data: keys.map((k) => ({ value: counts[k], itemStyle: { color: cssVar(colorFor[k]) } })),
        barMaxWidth: 44,
      }],
    });
  }

  private renderEpss(records: Vulnerability[]): void {
    const chart = this.inst("chartEpss");
    if (!chart) return;
    const buckets = epssHistogram(records);
    const labels = buckets.map((_, i) => `${i * 10}-${i * 10 + 10}%`);
    chart.setOption({
      grid: { ...baseGrid(), bottom: 44 },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle() },
      xAxis: { type: "category", data: labels, ...axisStyle(), axisLabel: { color: cssVar("--muted"), fontSize: 10, rotate: 40 } },
      yAxis: { type: "value", minInterval: 1, ...axisStyle() },
      series: [{ type: "bar", data: buckets, itemStyle: { color: cssVar("--accent") }, barMaxWidth: 30 }],
    });
  }

  private renderVendors(records: Vulnerability[]): void {
    const chart = this.inst("chartVendors");
    if (!chart) return;
    const top = topVendors(records, 10).reverse();
    chart.setOption({
      grid: { left: 120, right: 24, top: 12, bottom: 24 },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...tooltipStyle() },
      xAxis: { type: "value", minInterval: 1, ...axisStyle() },
      yAxis: { type: "category", data: top.map((t) => t.vendor), ...axisStyle() },
      series: [{
        type: "bar",
        data: top.map((t) => t.count),
        itemStyle: { color: cssVar("--accent"), borderRadius: [0, 3, 3, 0] },
        barMaxWidth: 16,
      }],
    });
  }

  private renderTimeToKev(records: Vulnerability[]): void {
    const chart = this.inst("chartTtk");
    if (!chart) return;
    const ttk = timeToKev(records);
    if (!ttk.length) {
      chart.setOption({
        grid: baseGrid(),
        title: { text: "No KEV records with both dates in view", left: "center", top: "center",
          textStyle: { color: cssVar("--muted-2"), fontSize: 12, fontWeight: "normal" } },
        xAxis: { show: false }, yAxis: { show: false }, series: [],
      });
      return;
    }
    chart.setOption({
      grid: baseGrid(),
      tooltip: {
        trigger: "item", ...tooltipStyle(),
        formatter: (p: { data: [number, number]; name: string }) =>
          `${p.name}: ${p.data[1]} days to KEV`,
      },
      xAxis: { type: "category", data: ttk.map((t) => t.cve), ...axisStyle(), axisLabel: { show: false } },
      yAxis: { type: "value", name: "days", nameTextStyle: { color: cssVar("--muted") }, ...axisStyle() },
      series: [{
        type: "bar",
        data: ttk.map((t) => ({ value: t.days, name: t.cve })),
        itemStyle: { color: cssVar("--p2") },
        barMaxWidth: 18,
      }],
    });
  }

  renderPulse(records: Vulnerability[]): void {
    const node = document.getElementById("pulseSpark");
    if (!node) return;
    if (!this.pulse) this.pulse = echarts.init(node, undefined, { renderer: "canvas" });
    const series = seriesByDay(records, (v) => v.published);
    this.pulse.setOption({
      grid: { left: 0, right: 0, top: 2, bottom: 2 },
      xAxis: { type: "category", show: false, data: series.dates, boundaryGap: false },
      yAxis: { type: "value", show: false },
      series: [{
        type: "line", data: series.counts, smooth: true, showSymbol: false,
        lineStyle: { color: cssVar("--accent"), width: 1.5 },
        areaStyle: { color: cssVar("--accent-soft") },
      }],
    });
  }

  resize(): void {
    for (const c of this.instances.values()) c.resize();
    this.pulse?.resize();
  }

  /** Re-render all charts after a theme change so colours refresh. */
  refreshTheme(records: Vulnerability[]): void {
    this.render(records);
    this.renderPulse(records);
  }
}
