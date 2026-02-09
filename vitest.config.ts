import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    browser: {
      provider: 'playwright',
      name: 'chromium',
      headless: true,
    },
  },
});
