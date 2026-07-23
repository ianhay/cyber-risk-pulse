import type { Methodology, Status } from "../types";
import { el, mount } from "../components/dom";

export function renderMethodology(root: HTMLElement, m: Methodology, status: Status): void {
  const rules = m.priority_rules as Record<string, { label?: string; description?: string }>;
  const ruleRows = Object.entries(rules).map(([tier, def]) =>
    el("tr", {}, [
      el("td", {}, [el("span", { class: "tier-code", "data-tier": tier.toUpperCase(), text: tier.toUpperCase() })]),
      el("td", { text: def.label ?? "" }),
      el("td", { text: def.description ?? "" }),
    ]),
  );

  const thresholdRows = Object.entries(m.thresholds).map(([k, v]) =>
    el("tr", {}, [el("td", {}, [el("code", { text: k })]), el("td", { class: "mono", text: String(v) })]),
  );

  mount(root,
    el("div", { class: "method" }, [
      el("h2", { class: "section__title", text: "How Cyber Risk Pulse prioritises" }),
      el("p", { text: m.statement }),

      el("h3", { text: "Threat-priority tiers" }),
      el("p", { text: "Every CVE is placed in exactly one tier. Rules are evaluated from P1 downward; the first match wins. CISA KEV membership always forces Priority 1." }),
      el("table", { class: "rule-table" }, [
        el("thead", {}, [el("tr", {}, [el("th", { text: "Tier" }), el("th", { text: "Label" }), el("th", { text: "Condition" })])]),
        el("tbody", {}, ruleRows),
      ]),

      el("h3", { text: "Thresholds" }),
      el("table", { class: "rule-table" }, [
        el("thead", {}, [el("tr", {}, [el("th", { text: "Setting" }), el("th", { text: "Value" })])]),
        el("tbody", {}, thresholdRows),
      ]),

      el("h3", { text: "Sources" }),
      el("ul", {}, [
        el("li", {}, [el("strong", { text: "CISA KEV. " }), "The authoritative catalogue of vulnerabilities known to be exploited in the wild. Membership is a hard signal and forces Priority 1."]),
        el("li", {}, [el("strong", { text: "NVD (NIST). " }), "CVE records, CVSS base metrics and CPE applicability. Fetched server-side on a schedule; the browser never calls NVD directly."]),
        el("li", {}, [el("strong", { text: "FIRST EPSS. " }), "A daily model estimating the probability a CVE will be exploited in the next 30 days. Used as a likelihood signal, never as impact."]),
      ]),

      el("h3", { text: "What this is not" }),
      el("p", {}, [
        "These tiers describe ", el("strong", { text: "external threat priority" }),
        " — how much attention a vulnerability warrants based on public exploitation and likelihood signals. They are ",
        el("strong", { text: "not asset-specific risk" }),
        ". Real risk depends on whether you run the affected software, how it is exposed, and what compensating controls you have. Always confirm applicability against your own inventory.",
      ]),

      el("h3", { text: "Limitations" }),
      el("ul", {}, [
        el("li", { text: "CPE vendor/product matching can be coarse; treat affected-product lists as a starting point." }),
        el("li", { text: "EPSS and CVSS are sometimes unavailable; missing values are shown as such and never treated as zero." }),
        el("li", { text: "The rolling window bounds NVD volume; all KEV entries are always included regardless of age." }),
      ]),

      el("p", { class: "meta-line", style: "margin-top:24px" , text:
        `Application v${status.app_version}${status.build_commit ? " · build " + status.build_commit.slice(0, 7) : ""}${status.fixture_mode ? " · demo dataset" : ""}` }),
    ]),
  );
}
