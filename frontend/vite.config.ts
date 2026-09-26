/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Everything is bundled locally - no CDN - so the UI works in an air-gapped network.
// In development /api is proxied to the backend started with `logsync serve`.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: true } },
  },
  test: { environment: "node" },
});
