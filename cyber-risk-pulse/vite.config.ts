import { defineConfig } from "vite";

// GitHub Project Pages serve from /<repo>/. Set VITE_BASE at build time in CI
// to the repository name (e.g. "/cyber-risk-pulse/"). Defaults to "/" so
// local dev and user/organisation Pages work without configuration.
const base = process.env.VITE_BASE ?? "/";

export default defineConfig({
  base,
  build: {
    target: "es2021",
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.ts"],
  },
});
