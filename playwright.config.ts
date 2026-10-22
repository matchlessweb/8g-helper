import { defineConfig } from '@playwright/test'

// The smoke test runs against the built, prerendered page (npm run build first), or against BASE_URL when set.
const external = process.env.BASE_URL

export default defineConfig({
  testDir: 'test/e2e',
  forbidOnly: true,
  retries: 0,
  reporter: 'list',
  use: { baseURL: external ?? 'http://127.0.0.1:4173', trace: 'retain-on-failure' },
  webServer: external
    ? undefined
    : { command: 'npx vite preview --host 127.0.0.1 --port 4173 --strictPort', url: 'http://127.0.0.1:4173', reuseExistingServer: false },
})
