import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run build` emits frontend/dist, which the Django app serves via WhiteNoise.
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 700 },
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8787" } },
});
