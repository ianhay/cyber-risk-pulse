import type { Vulnerability } from "../types";
import { el, mount } from "./dom";
import { fmtDate, fmtScore, pct } from "./format";

let lastFocused: HTMLElement | null = null;

function block(term: string, ...val: (Node | string | null | false)[]) {
  return el("div", { class: "dl__block" }, [
    el("div", { class: "dl__term", text: term }),
    el("div", { class: "dl__val" }, val.filter(Boolean) as (Node | string)[]),
  ]);
}

export function initDetailPanel(): { overlay: HTMLElement; panel: HTMLElement } {
  const overlay = document.getElementById("detailOverlay")!;
  const panel = document.getElementById("detailPanel")!;
  overlay.addEventListener("click", closeDetail);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && panel.getAttribute("data-open") === "true") closeDetail();
  });
  return { overlay, panel };
}

export function closeDetail(): void {
  const overlay = document.getElementById("detailOverlay")!;
  const panel = document.getElementById("detailPanel")!;
  panel.setAttribute("data-open", "false");
  overlay.setAttribute("data-open", "false");
  panel.setAttribute("aria-hidden", "true");
  if (lastFocused) lastFocused.focus();
}

export function openDetail(v: Vulnerability): void {
  const overlay = document.getElementById("detailOverlay")!;
  const panel = document.getElementById("detailPanel")!;
  lastFocused = document.activeElement as HTMLElement;

  const head = el("div", { class: "detail__head" }, [
    el("div", {}, [
      el("div", { class: "tier-code", "data-tier": v.tier, text: v.tier }),
      el("div", { class: "cve-id", text: v.id, style: "margin-top:6px;font-size:1rem" }),
    ]),
    el("button", { class: "detail__close", type: "button", "aria-label": "Close", text: "✕" }),
  ]);
  (head.querySelector(".detail__close") as HTMLButtonElement).addEventListener("click", closeDetail);

  const flagNotes: (Node | string)[] = [];
  if (v.flags.includes("no_nvd_record")) flagNotes.push(el("div", { class: "warn-note", text: "No NVD record found; details are limited to the KEV catalogue entry." }));
  if (v.flags.includes("no_cvss")) flagNotes.push(el("div", { class: "warn-note", text: "No CVSS metric published. Severity is shown as unavailable, not zero." }));
  if (v.flags.includes("no_epss")) flagNotes.push(el("div", { class: "warn-note", text: "No EPSS score available for this CVE." }));

  const cvssVal = v.cvss
    ? `${fmtScore(v.cvss.score)} ${v.cvss.severity ?? ""} (v${v.cvss.version})`
    : "Not available";
  const epssVal = v.epss
    ? `${pct(v.epss.p)} probability · ${pct(v.epss.pct)} percentile`
    : "Not available";

  const kevBlock = v.kev
    ? block("Known exploited (CISA KEV)",
        el("div", { text: `Added ${fmtDate(v.kev.dateAdded)} · Due ${fmtDate(v.kev.dueDate)}` }),
        v.kev.ransomware ? el("div", { text: `Ransomware campaign use: ${v.kev.ransomware}` }) : null,
        v.kev.requiredAction ? el("div", { style: "margin-top:6px", text: v.kev.requiredAction }) : null,
      )
    : null;

  const refs = v.refs.length
    ? block("References",
        el("div", { class: "ref-list" }, v.refs.slice(0, 12).map((r) =>
          el("a", { href: r.url, target: "_blank", rel: "noopener noreferrer", text: r.url }),
        )),
      )
    : null;

  const body = el("div", { class: "detail__body" }, [
    block("Description", el("div", { text: v.desc || "No description provided." })),
    ...flagNotes,
    block("Why this priority",
      el("ul", { class: "reason-list" }, v.reasons.map((r) => el("li", { text: r }))),
    ),
    block("CVSS", el("span", { class: "mono", text: cvssVal }),
      v.cvss?.vector ? el("div", { class: "mono", style: "font-size:11px;color:var(--muted-2);margin-top:4px", text: v.cvss.vector }) : null),
    block("EPSS", el("span", { class: "mono", text: epssVal })),
    kevBlock,
    v.vendors.length ? block("Affected", el("div", { text: v.vendors.join(", ") }),
      v.products.length ? el("div", { class: "meta-line", text: `Products: ${v.products.join(", ")}` }) : null,
      el("div", { class: "warn-note", text: "Vendor/product names come from CPE matching and may be broad. Confirm against your own inventory." })) : null,
    v.cwes.length ? block("Weaknesses (CWE)", el("div", { class: "mono", text: v.cwes.join(", ") })) : null,
    block("Dates",
      el("div", { text: `Published: ${fmtDate(v.published)}` }),
      el("div", { text: `Last modified: ${fmtDate(v.modified)}` }),
      v.status ? el("div", { class: "meta-line", text: `NVD status: ${v.status}` }) : null),
    refs,
  ]);

  mount(panel, head, body);
  panel.setAttribute("data-open", "true");
  panel.setAttribute("aria-hidden", "false");
  overlay.setAttribute("data-open", "true");
  (panel.querySelector(".detail__close") as HTMLButtonElement).focus();
}
