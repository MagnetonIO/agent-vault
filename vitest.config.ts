import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts", "test/**/*.test.ts"],
    // Daemon fixtures start in a beforeEach. A Windows cold start takes 2-10 s alone and the CLI
    // e2e file competes for the same CPU, so the 10 s default hook timeout is too tight there.
    hookTimeout: 30_000,
  },
});
