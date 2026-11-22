import { defineConfig, type Plugin } from "vite";

const externalEasyTier: Plugin = {
  name: "external-easytier-browser",
  enforce: "pre",
  resolveId(id) {
    if (id === "@easytier/browser") {
      return { id, external: true };
    }
    return null;
  },
};

export default defineConfig({
  plugins: [externalEasyTier],
  build: {
    rollupOptions: {
      input: {
        index: "index.html",
        callback: "callback.html",
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
  },
});
