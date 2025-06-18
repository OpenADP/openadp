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
    VitePWA({
      registerType: 'autoUpdate',
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/.*\.openadp\.org\/.*/i,
            handler: 'NetworkFirst',
            options: {
              cacheName: 'openadp-api-cache',
              expiration: {
                maxEntries: 50,
                maxAgeSeconds: 60 * 60 * 24 // 24 hours
              },
              cacheKeyWillBeUsed: async ({ request }) => {
                // Don't cache sensitive API calls
                if (request.url.includes('secret') || request.url.includes('auth')) {
                  return null;
                }
                return request.url;
              }
            }
          },
          {
            urlPattern: /^https:\/\/.*\.r2\.cloudflarestorage\.com\/.*/i,
            handler: 'NetworkFirst',
            options: {
              cacheName: 'r2-storage-cache',
              expiration: {
                maxEntries: 100,
                maxAgeSeconds: 60 * 60 // 1 hour
              }
            }
          }
        ]
      },
      includeAssets: ['favicon.ico', 'apple-touch-icon.png', 'masked-icon.svg'],
      manifest: {
        name: 'Private Notes - OpenADP Demo',
        short_name: 'Private Notes',
        description: 'Secure notes with distributed cryptographic trust',
        theme_color: '#1e40af',
        background_color: '#ffffff',
        display: 'standalone',
        orientation: 'portrait-primary',
        scope: '/',
        start_url: '/',
        categories: ['productivity', 'utilities', 'security'],
        icons: [
          {
            src: 'icons/pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'icons/pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          },
          {
            src: 'icons/pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any maskable'
          }
        ],
        shortcuts: [
          {
            name: 'New Note',
            short_name: 'New Note',
            description: 'Create a new encrypted note',
            url: '/?action=new',
            icons: [
              {
                src: 'icons/new-note-96x96.png',
                sizes: '96x96'
              }
            ]
          },
          {
            name: 'Sync Notes',
            short_name: 'Sync',
            description: 'Synchronize notes across devices',
            url: '/?action=sync',
            icons: [
              {
                src: 'icons/sync-96x96.png',
                sizes: '96x96'
              }
            ]
          }
        ],
        screenshots: [
          {
            src: 'screenshots/desktop-wide.png',
            sizes: '1280x720',
            type: 'image/png',
            form_factor: 'wide',
            label: 'Private Notes on desktop'
          },
          {
            src: 'screenshots/mobile-narrow.png',
            sizes: '375x667',
            type: 'image/png',
            form_factor: 'narrow',
            label: 'Private Notes on mobile'
          }
        ]
      },
      devOptions: {
        enabled: true,
        type: 'module'
      }
    })
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