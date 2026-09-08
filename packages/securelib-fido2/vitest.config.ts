import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**'],
    // Real hardware tests wait on a physical touch, which takes longer
    // than vitest's default 5s — same reasoning as securelib-piv's config.
    testTimeout: 30000,
  },
});
