import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  test: {
    environment: "node",
    include: ["packages/*/test/**/*.test.ts"]
  },
  resolve: {
    alias: {
      "@safebrowse/approval-broker": resolve(__dirname, "packages/approval-broker/src/index.ts"),
      "@safebrowse/core": resolve(__dirname, "packages/core/src/index.ts"),
      "@safebrowse/kb-tools": resolve(__dirname, "packages/kb-tools/src/index.ts"),
      "@safebrowse/daemon": resolve(__dirname, "packages/daemon/src/index.ts"),
      "@safebrowse/playwright-adapter": resolve(__dirname, "packages/playwright-adapter/src/index.ts")
    }
  }
});

