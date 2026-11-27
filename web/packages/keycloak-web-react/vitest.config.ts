import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { '@p2-inc/keycloak-web': fileURLToPath(new URL('../keycloak-web/src/index.ts', import.meta.url)) },
  },
  test: {
    include: ['test/**/*.test.tsx'],
    environment: 'jsdom',
  },
});
