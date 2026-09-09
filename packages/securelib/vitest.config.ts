import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**'],
    coverage: {
      provider: 'v8',
      // Scoped to this package's own src/ — registry.ts's dynamic import
      // of @trinoris/securelib-piv/-fido2 (exercised by some tests) would
      // otherwise pull their files into this package's report too.
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
