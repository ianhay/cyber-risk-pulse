// Minimal element helper. Deliberately uses textContent for all text so that
// upstream-provided strings (descriptions, vendor names, required actions) can
// never inject markup. No code path assigns innerHTML from feed data.

type Attrs = Record<string, string | number | boolean | null | undefined>;
type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = String(v);
    else if (k === "text") node.textContent = String(v);
    else if (k.startsWith("data-") || k === "role" || k.startsWith("aria-")) {
      node.setAttribute(k, String(v));
    } else if (k in node) {
      // Typed DOM properties (e.g. href, value, type).
      (node as unknown as Record<string, unknown>)[k] = v;
    } else {
      node.setAttribute(k, String(v));
    }
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: Element): void {
  node.replaceChildren();
}

export function mount(node: Element, ...children: Child[]): void {
  node.replaceChildren();
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
}
