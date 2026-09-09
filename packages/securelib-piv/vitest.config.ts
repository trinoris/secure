import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**'],
    testTimeout: 20000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
      // `json-summary` alongside the default text table: CI's coverage
      // badge (scripts/generate-coverage-badge.mjs) reads
      // coverage/coverage-summary.json from every package, not this
      // table's own text output.
      reporter: ['text', 'json-summary'],
      thresholds: {
        branches: 90,
      },
    },
  },
});
