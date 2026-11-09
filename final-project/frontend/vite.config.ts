import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

// API routes the SPA talks to. In dev these are proxied to the FastAPI app
// (default :8080); in production the SPA is served same-origin from /ui so the
// same absolute paths resolve against the app itself.
const API_PREFIXES = ["/health", "/info", "/targets", "/scans", "/findings", "/docs", "/openapi.json"];
const API_TARGET = process.env.ONO_API ?? "http://localhost:8080";

export default defineConfig({
  // Served by FastAPI under /ui, so assets must resolve there.
  base: "/ui/",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      API_PREFIXES.map((p) => [p, { target: API_TARGET, changeOrigin: true }]),
    ),
  },
  build: {
    // FastAPI serves this directory via StaticFiles at /ui.
    outDir: resolve(__dirname, "../src/ono/webui/static"),
    emptyOutDir: true,
  },
});
