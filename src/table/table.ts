import type { Store } from "../data/store";
import type { SortKey } from "../data/derive";
import type { Vulnerability } from "../types";
import { sortRecords } from "../data/derive";
import { el, mount } from "../components/dom";
import { fmtAge, fmtDate, fmtScore, pct, primaryVendor } from "../components/format";
import { openDetail } from "../components/detailPanel";

const PAGE = 60;

interface Column {
  key: string;
  label: string;
  sort?: SortKey;
  optional?: boolean;
}

const COLUMNS: Column[] = [
  { key: "rail", label: "" },
  { key: "priority", label: "Priority", sort: "priority" },
  { key: "cve", label: "CVE", sort: "cve" },
  { key: "desc", label: "Description", optional: true },
  { key: "flags", label: "Flags" },
  { key: "cvss", label: "CVSS", sort: "cvss" },
  { key: "epss", label: "EPSS", sort: "epss" },
  { key: "published", label: "Published", sort: "published", optional: true },
];

export function createTable(root: HTMLElement, store: Store) {
  let sortKey: SortKey = "priority";
  let sortDir: "asc" | "desc" = "asc";
  let observer: IntersectionObserver | null = null;

  function headerCell(col: Column): HTMLElement {
    const attrs: Record<string, string> = { class: col.sort ? "sortable" : "" };
    if (col.optional) attrs.class += " col-optional";
    if (col.sort) {
      attrs["aria-sort"] = sortKey === col.sort ? (sortDir === "asc" ? "ascending" : "descending") : "none";
      attrs.role = "button";
      attrs.tabindex = "0";
    }
    const th = el("th", attrs, [col.label]);
    if (col.sort) {
      const onSort = () => {
        if (sortKey === col.sort) sortDir = sortDir === "asc" ? "desc" : "asc";
        else {
          sortKey = col.sort!;
          sortDir = col.sort === "cve" ? "asc" : "desc";
        }
        render();
      };
      th.addEventListener("click", onSort);
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSort(); }
      });
    }
    return th;
  }

  function row(v: Vulnerability): HTMLElement {
    const copyBtn = el("button", { class: "copy-btn", type: "button", title: "Copy CVE ID", "aria-label": `Copy ${v.id}`, text: "copy" });
    copyBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      navigator.clipboard?.writeText(v.id).then(() => {
        copyBtn.textContent = "✓";
        window.setTimeout(() => (copyBtn.textContent = "copy"), 1200);
      });
    });

    const flags: (Node | string)[] = [];
    if (v.kev) flags.push(el("span", { class: "badge badge--kev", text: "KEV" }));
    if ((v.kev?.ransomware ?? "").toLowerCase() === "known") flags.push(el("span", { class: "badge badge--ransom", text: "RANSOM" }));
    if (!flags.length) flags.push(el("span", { class: "badge badge--muted", text: "—" }));

    const cvssCell = v.cvss && v.cvss.score !== null
      ? el("span", { class: "metric" }, [
          el("span", { class: `sev-dot sev-${v.cvss.severity ?? "UNKNOWN"}` }),
          fmtScore(v.cvss.score),
        ])
      : el("span", { class: "metric metric--na", text: "n/a" });

    const epssCell = v.epss && v.epss.p !== null
      ? el("span", { class: "metric", text: pct(v.epss.p) })
      : el("span", { class: "metric metric--na", text: "n/a" });

    const tr = el("tr", { tabindex: "0", role: "button", "aria-label": `${v.id}, ${v.tier}` }, [
      el("td", { class: "rail" }, [el("span", { class: "rail__bar", "data-tier": v.tier })]),
      el("td", {}, [el("span", { class: "tier-code", "data-tier": v.tier, text: v.tier })]),
      el("td", {}, [
        el("div", { class: "cve-cell" }, [el("span", { class: "cve-id", text: v.id }), copyBtn]),
      ]),
      el("td", { class: "col-optional" }, [
        el("div", { class: "desc-cell", text: v.desc || "—" }),
        el("div", { class: "meta-line", text: `${primaryVendor(v)}${v.products.length ? " · " + v.products[0] : ""}` }),
      ]),
      el("td", {}, [el("div", { style: "display:flex;gap:4px;flex-wrap:wrap" }, flags)]),
      el("td", {}, [cvssCell]),
      el("td", {}, [epssCell]),
      el("td", { class: "col-optional" }, [
        el("div", { text: fmtDate(v.published) }),
        el("div", { class: "meta-line", text: fmtAge(v.published) }),
      ]),
    ]);
    const open = () => openDetail(v);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); open(); }
    });
    return tr;
  }

  function render(): void {
    observer?.disconnect();
    const sorted = sortRecords(store.filtered(), sortKey, sortDir);

    if (!sorted.length) {
      mount(root,
        el("div", { class: "empty-state" }, [
          el("div", { class: "empty-state__title", text: "No vulnerabilities match" }),
          el("div", { text: "Widen the time window or clear a filter to see more." }),
        ]),
      );
      return;
    }

    const thead = el("thead", {}, [el("tr", {}, COLUMNS.map(headerCell))]);
    const tbody = el("tbody", {});
    const table = el("table", { class: "qtable" }, [thead, tbody]);
    const scroll = el("div", { class: "queue__scroll" }, [table]);
    const foot = el("div", { class: "queue__foot" });
    mount(root, scroll, foot);

    let shown = 0;
    const appendPage = () => {
      const next = sorted.slice(shown, shown + PAGE);
      for (const v of next) tbody.append(row(v));
      shown += next.length;
      mount(foot,
        shown < sorted.length
          ? el("span", { class: "section__note", text: `Showing ${shown} of ${sorted.length}` })
          : el("span", { class: "section__note", text: `${sorted.length} shown` }),
      );
      if (shown < sorted.length) {
        const sentinel = el("div", { style: "height:1px" });
        foot.append(sentinel);
        observer = new IntersectionObserver((entries) => {
          if (entries.some((en) => en.isIntersecting)) {
            observer?.disconnect();
            appendPage();
          }
        }, { rootMargin: "300px" });
        observer.observe(sentinel);
      }
    };
    appendPage();
  }

  return { render };
}
