/**
 * ZeroNode - Service Worker & Self-Updater
 * Cache Version: v1.2.2
 */

const CACHE_VERSION = 'v1.2.2';
const CACHE_NAME = `zeronode-${CACHE_VERSION}`;

// Pre-cached core app shell assets
const PRECACHE_ASSETS = [
  '/',
  '/manifest.json',
  '/offline',
  '/static/manifest.json',
  '/static/css/fonts.css',
  '/static/css/style.css',
  '/static/js/tailwind.js',
  '/static/js/main.js',
  '/static/js/drive.js',
  '/static/js/backup_live.js',
  '/static/js/pwa-updater.js',
  '/static/js/page-transition.js',
  '/static/vendor/marked.min.js',
  '/static/vendor/turndown.js',
  '/static/icon.ico',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/static/icons/icon-maskable-192.png',
  '/static/icons/icon-maskable-512.png',
  '/static/icons/apple-touch-icon.png',
  '/static/icons/favicon-32.png'
];

// 1. Install Event: Cache Core App Shell
self.addEventListener('install', (event) => {
  self.skipWaiting();
  console.log(`[SW] Installing ZeroNode Service Worker (${CACHE_VERSION})...`);
  
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      // Individual cache puts to prevent a single missing asset from failing installation
      const results = await Promise.allSettled(
        PRECACHE_ASSETS.map(async (url) => {
          try {
            const response = await fetch(url, { cache: 'no-cache' });
            if (response.ok) {
              await cache.put(url, response);
            }
          } catch (err) {
            console.debug(`[SW] Pre-cache skipped for ${url}:`, err.message);
          }
        })
      );
      console.log(`[SW] Pre-cache completed (${results.filter(r => r.status === 'fulfilled').length}/${PRECACHE_ASSETS.length} cached).`);
    })
  );
});

// 2. Activate Event: Clean Stale Caches and Claim Clients
self.addEventListener('activate', (event) => {
  console.log(`[SW] Activating ZeroNode Service Worker (${CACHE_VERSION})...`);
  
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key.startsWith('zeronode-') && key !== CACHE_NAME) {
            console.log(`[SW] Clearing outdated cache: ${key}`);
            return caches.delete(key);
          }
        })
      );
    }).then(async () => {
      // Clear any accidental /api/ keys that may have entered the cache
      try {
        const currentCache = await caches.open(CACHE_NAME);
        const keys = await currentCache.keys();
        await Promise.all(
          keys.map((k) => {
            if (k.url.includes('/api/')) {
              console.log('[SW] Removing leaked API request from cache:', k.url);
              return currentCache.delete(k);
            }
          })
        );
      } catch (err) {
        console.debug('[SW] Cache cleanup skipped:', err.message);
      }
    }).then(() => {
      console.log(`[SW] Claiming clients for ${CACHE_VERSION}`);
      return self.clients.claim();
    })
  );
});

// 3. Message Event: Remote Control (Skip Waiting & Status)
self.addEventListener('message', (event) => {
  if (!event.data) return;

  if (event.data.type === 'SKIP_WAITING') {
    console.log('[SW] SKIP_WAITING received. Activating new worker...');
    self.skipWaiting();
  } else if (event.data.type === 'GET_VERSION') {
    if (event.ports && event.ports[0]) {
      event.ports[0].postMessage({
        version: CACHE_VERSION,
        cacheName: CACHE_NAME
      });
    }
  } else if (event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then((keys) => {
        return Promise.all(keys.map((k) => caches.delete(k)));
      }).then(() => {
        if (event.ports && event.ports[0]) {
          event.ports[0].postMessage({ cleared: true });
        }
      })
    );
  }
});

// 4. Fetch Event: Routing & Cache Strategy
self.addEventListener('fetch', (event) => {
  const req = event.request;
  
  // Only handle GET requests
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Ignore cross-origin and chrome-extension schemes
  if (url.origin !== self.location.origin) return;

  const pathname = url.pathname;

  // STRICT BYPASS: Never intercept any API calls, dynamic payloads, web sockets, or auth endpoints
  const isBypass = 
    pathname.includes('/api/') ||
    pathname.startsWith('/auth/') ||
    pathname.startsWith('/ws/') ||
    pathname.includes('/events') ||
    pathname.includes('/chunk') ||
    pathname.includes('/download') ||
    pathname.includes('/stream') ||
    pathname.includes('/status') ||
    req.headers.has('range') ||
    url.searchParams.has('nocache') ||
    url.searchParams.has('t');

  if (isBypass) {
    // Let browser network stack handle directly without CacheStorage intervention
    return;
  }

  // Strategy A: Static Assets (/static/*) -> Stale-While-Revalidate
  if (pathname.startsWith('/static/')) {
    event.respondWith(
      caches.open(CACHE_NAME).then(async (cache) => {
        const cachedResponse = await cache.match(req);

        // Fetch fresh copy in background to update cache
        const fetchPromise = fetch(req)
          .then((networkResponse) => {
            if (networkResponse && networkResponse.status === 200) {
              cache.put(req, networkResponse.clone());
            }
            return networkResponse;
          })
          .catch(() => cachedResponse);

        // Return cached immediately if available, else await network
        return cachedResponse || fetchPromise;
      })
    );
    return;
  }

  // Strategy B: Page Navigations (HTML) -> Network-First with Offline Fallback
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
          }
          return networkResponse;
        })
        .catch(async () => {
          // Network failed, check cache for requested page
          const cache = await caches.open(CACHE_NAME);
          const cachedPage = await cache.match(req);
          if (cachedPage) return cachedPage;

          // Fallback to offline page
          const offlinePage = await cache.match('/offline');
          if (offlinePage) return offlinePage;

          return new Response('Network offline. Please reconnect to access ZeroNode.', {
            status: 503,
            headers: { 'Content-Type': 'text/plain' }
          });
        })
    );
    return;
  }

  // For any other GET request (e.g. dynamic non-static resources), do NOT touch CacheStorage
  return;
});
