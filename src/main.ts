// Self-hosted fonts (no external CDN; satisfies a strict connect-src CSP).
import "@fontsource/space-grotesk/400.css";
import "@fontsource/space-grotesk/600.css";
import "@fontsource/space-grotesk/700.css";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/700.css";

import "./styles/tokens.css";
import "./styles/main.css";

import { boot } from "./app";

boot().catch((err) => {
  // Last-resort guard so a boot failure is visible rather than silent.
  console.error(err);
  const slot = document.getElementById("errorSlot");
  if (slot) slot.textContent = "The dashboard failed to start. See the browser console for details.";
});
