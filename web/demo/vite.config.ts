import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const src = (path: string) => fileURLToPath(new URL(path, import.meta.url));

// The demo builds the packages from source, so a change in packages/ shows up without a build.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@p2-inc/keycloak-web-react': src('../packages/keycloak-web-react/src/index.ts'),
      '@p2-inc/keycloak-web': src('../packages/keycloak-web/src/index.ts'),
    },
  },
  server: { port: 5173, strictPort: true },
  build: {
    rollupOptions: { input: { main: src('index.html'), callback: src('callback.html') } },
  },
});
