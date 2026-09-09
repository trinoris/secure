import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**', 'src/**/*.integration.test.ts'],
    coverage: {
      provider: 'v8',
      // Scoped to this package's own src/ — without this, v8's coverage
      // provider also reports on @trinoris/securelib-piv/-fido2, pulled in
      // transitively by the registry.ts dynamic-import path some tests
      // exercise, double-counting code that has its own package and its
      // own threshold.
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/*.integration.test.ts'],
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
