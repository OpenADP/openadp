// Ghost Notes Service Worker
// Provides offline functionality and basic caching

const CACHE_NAME = 'ghost-notes-v1';
const urlsToCache = [
    './',
    './index.html',
    './styles.css',
    './app.js',
    './manifest.json'
];

// Install event - cache resources
self.addEventListener('install', (event) => {
    console.log('👻 Service Worker installing...');
    
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('📦 Caching app resources');
                return cache.addAll(urlsToCache);
            })
            .then(() => {
                console.log('✅ Cache populated');
                return self.skipWaiting();
            })
    );
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
    console.log('👻 Service Worker activating...');
    
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('🗑️ Removing old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => {
            console.log('✅ Service Worker activated');
            return self.clients.claim();
        })
    );
});

// Fetch event - serve from cache when offline
self.addEventListener('fetch', (event) => {
    // Only handle GET requests
    if (event.request.method !== 'GET') {
        return;
    }
    
    // Skip chrome-extension and other non-http requests
    if (!event.request.url.startsWith('http')) {
        return;
    }
    
    event.respondWith(
        caches.match(event.request)
            .then((response) => {
                // Return cached version or fetch from network
                if (response) {
                    console.log('📁 Serving from cache:', event.request.url);
                    return response;
                }
                
                console.log('🌐 Fetching from network:', event.request.url);
                return fetch(event.request)
                    .then((response) => {
                        // Don't cache non-successful responses
                        if (!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }
                        
                        // Clone response to cache it
                        const responseToCache = response.clone();
                        
                        caches.open(CACHE_NAME)
                            .then((cache) => {
                                cache.put(event.request, responseToCache);
                            });
                        
                        return response;
                    })
                    .catch(() => {
                        // Network failed, try to serve a fallback
                        if (event.request.mode === 'navigate') {
                            return caches.match('./index.html');
                        }
                    });
            })
    );
});

// Background sync for future cloud storage features
self.addEventListener('sync', (event) => {
    if (event.tag === 'ghost-notes-sync') {
        console.log('🔄 Background sync triggered');
        // Future: sync with Cloudflare R2
    }
});

// Push notifications for collaborative features (future)
self.addEventListener('push', (event) => {
    if (event.data) {
        const data = event.data.json();
        console.log('📨 Push notification received:', data);
        
        // Future: show notifications for collaborative editing
    }
});

// Message handling from main app
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    if (event.data && event.data.type === 'CACHE_UPDATE') {
        console.log('🔄 Manual cache update requested');
        // Refresh cache when app updates
    }
}); 