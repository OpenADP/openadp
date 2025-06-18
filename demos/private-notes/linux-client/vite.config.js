import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  root: 'src',
  publicDir: '../public',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: 'src/index.html',
        offline: 'src/offline.html'
      }
    },
    // Optimize for production
    minify: 'esbuild',
    sourcemap: true,
    target: 'es2020'
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    open: true,
    cors: true,
    // Enable HTTPS for PWA features in development
    https: false, // Set to true if you have SSL certificates
    headers: {
      'Cross-Origin-Embedder-Policy': 'credentialless',
      'Cross-Origin-Opener-Policy': 'same-origin'
    }
  },
  preview: {
    port: 3001,
    host: '0.0.0.0'
  },
  plugins: [
    // VitePWA temporarily disabled - will re-enable after creating icons
  ],
  define: {
    // Define global constants
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    __BUILD_DATE__: JSON.stringify(new Date().toISOString()),
    __DEV__: JSON.stringify(process.env.NODE_ENV === 'development')
  },
  optimizeDeps: {
    include: ['idb', 'uuid', 'dompurify']
  },
  // Security headers for development
  server: {
    ...{
      host: '0.0.0.0',
      port: 3000,
      open: true,
      cors: true
    },
    headers: {
      // Enable SharedArrayBuffer for crypto operations
      'Cross-Origin-Embedder-Policy': 'credentialless',
      'Cross-Origin-Opener-Policy': 'same-origin',
      // Security headers
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
  }
}); 