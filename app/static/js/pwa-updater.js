/**
 * ZeroNode - PWA Lifecycle & Updater
 * Handles Service Worker registration, background update detection,
 * non-intrusive update prompt banners, and native app install prompts.
 */

(function () {
  'use strict';

  // Global state
  let swRegistration = null;
  let deferredInstallPrompt = null;
  let isRefreshing = false;

  const PWA = {
    registration: null,
    updateAvailable: false,

    /**
     * Initialize Service Worker and PWA event listeners
     */
    async init() {
      if (!('serviceWorker' in navigator)) {
        console.debug('[PWA] Service workers are not supported by this browser.');
        return;
      }

      // Proactively purge old caches and sanitize any leaked /api/ endpoints
      if ('caches' in window) {
        caches.keys().then((keys) => {
          keys.forEach((key) => {
            if (key.startsWith('zeronode-') && key !== 'zeronode-v1.2.1') {
              console.log('[PWA] Purging obsolete cache store:', key);
              caches.delete(key);
            } else {
              caches.open(key).then((cache) => {
                cache.keys().then((requests) => {
                  requests.forEach((req) => {
                    if (req.url.includes('/api/')) {
                      console.log('[PWA] Sanitizing stale cached API entry:', req.url);
                      cache.delete(req);
                    }
                  });
                });
              });
            }
          });
        });
      }

      try {
        // Register root service worker
        const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
        swRegistration = reg;
        PWA.registration = reg;
        console.log('[PWA] Service Worker registered with scope:', reg.scope);

        // Check if an updated worker is already waiting (e.g. from previous tab/visit)
        if (reg.waiting) {
          PWA.notifyUpdateReady(reg.waiting);
        }

        // Detect new incoming service workers
        reg.addEventListener('updatefound', () => {
          const newWorker = reg.installing;
          if (!newWorker) return;

          console.log('[PWA] New Service Worker installing in background...');

          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed') {
              if (navigator.serviceWorker.controller) {
                // An active controller exists, so this new worker is an UPDATE
                console.log('[PWA] New version installed and waiting for activation.');
                PWA.notifyUpdateReady(newWorker);
              } else {
                // First install, content is pre-cached for offline use
                console.log('[PWA] App shell pre-cached for offline readiness.');
              }
            }
          });
        });

        // Controller change listener for seamless reloads
        navigator.serviceWorker.addEventListener('controllerchange', () => {
          if (!isRefreshing) {
            isRefreshing = true;
            console.log('[PWA] Controller changed. Reloading page with new assets...');
            window.location.reload();
          }
        });

        // Setup periodic update checks (every 30 minutes)
        setInterval(() => {
          PWA.checkForUpdates();
        }, 30 * 60 * 1000);

        // Check for updates when user returns to the tab
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible') {
            PWA.checkForUpdates();
          }
        });

        window.addEventListener('focus', () => {
          PWA.checkForUpdates();
        });

      } catch (err) {
        console.warn('[PWA] Service Worker registration failed:', err);
      }

      // Initialize install prompt listeners
      PWA.initInstallPrompt();

      // Initialize network connectivity listeners
      PWA.initConnectivityMonitor();
    },

    /**
     * Check if a newer version or service worker is available on the server
     */
    async checkForUpdates() {
      if (!swRegistration) return;

      try {
        console.log('[PWA] Checking server for Service Worker updates...');
        await swRegistration.update();

        // Also query version API to check server build
        const res = await fetch('/api/version?t=' + Date.now(), { cache: 'no-store' });
        if (res.ok) {
          const data = await res.json();
          console.debug('[PWA] Remote app version:', data.version, 'build:', data.build);
        }
      } catch (err) {
        console.debug('[PWA] Background update check skipped (network offline or busy):', err.message);
      }
    },

    /**
     * Display update banner and navbar triggers
     */
    notifyUpdateReady(worker) {
      PWA.updateAvailable = true;

      // Reveal nav buttons
      const navBtn = document.getElementById('pwa-update-nav-btn');
      if (navBtn) {
        navBtn.classList.remove('hidden');
        navBtn.classList.add('inline-flex');
      }

      const mobileBtn = document.getElementById('pwa-update-mobile-btn');
      if (mobileBtn) {
        mobileBtn.classList.remove('hidden');
        mobileBtn.classList.add('flex');
      }

      // If user chose 'LATER' during this session, don't nag with floating banner
      if (sessionStorage.getItem('znode_pwa_dismissed') === '1') {
        return;
      }

      const banner = document.getElementById('pwa-update-banner');
      if (banner) {
        banner.classList.remove('hidden');
        banner.classList.add('flex');
      }

      console.log('⚡ [PWA] Client app shell update ready.');
    },

    dismissUpdate() {
      sessionStorage.setItem('znode_pwa_dismissed', '1');
      const banner = document.getElementById('pwa-update-banner');
      if (banner) {
        banner.classList.add('hidden');
        banner.classList.remove('flex');
      }
    },

    /**
     * Tell the waiting service worker to skip waiting and activate immediately
     */
    applyUpdate() {
      sessionStorage.removeItem('znode_pwa_dismissed');
      const banner = document.getElementById('pwa-update-banner');
      if (banner) {
        const btn = banner.querySelector('button');
        if (btn) {
          btn.innerHTML = `<span class="inline-block animate-spin mr-2">⟳</span> ACTIVATING...`;
          btn.disabled = true;
        }
      }

      if (swRegistration && swRegistration.waiting) {
        swRegistration.waiting.postMessage({ type: 'SKIP_WAITING' });
      } else {
        // Fallback hard reload
        window.location.reload();
      }
    },

    /**
     * Setup native beforeinstallprompt listener
     */
    initInstallPrompt() {
      window.addEventListener('beforeinstallprompt', (e) => {
        // Prevent Chrome 67 and earlier from automatically showing the prompt
        e.preventDefault();
        deferredInstallPrompt = e;
        console.log('[PWA] Native app install prompt available.');

        // Reveal install button in navigation
        const installBtn = document.getElementById('pwa-install-btn');
        if (installBtn) {
          installBtn.classList.remove('hidden');
          installBtn.classList.add('inline-flex');
        }

        const mobileInstallBtn = document.getElementById('mobile-pwa-install-btn');
        if (mobileInstallBtn) {
          mobileInstallBtn.classList.remove('hidden');
          mobileInstallBtn.classList.add('flex');
        }
      });

      window.addEventListener('appinstalled', () => {
        deferredInstallPrompt = null;
        console.log('[PWA] ZeroNode successfully installed as native application.');
        
        // Hide install buttons
        const installBtn = document.getElementById('pwa-install-btn');
        if (installBtn) installBtn.classList.add('hidden');

        const mobileInstallBtn = document.getElementById('mobile-pwa-install-btn');
        if (mobileInstallBtn) mobileInstallBtn.classList.add('hidden');

        if (window.ZNodeDialog) {
          window.ZNodeDialog.alert('ZeroNode installed successfully to your system application launcher.', 'APP INSTALLED');
        }
      });
    },

    /**
     * Trigger native PWA install prompt
     */
    async installApp() {
      if (!deferredInstallPrompt) {
        if (window.ZNodeDialog) {
          window.ZNodeDialog.alert('Application is already installed or your browser does not support automatic installation. You can add it via your browser menu: "Install App" or "Add to Home Screen".', 'INSTALL PWA');
        }
        return;
      }

      deferredInstallPrompt.prompt();
      const choiceResult = await deferredInstallPrompt.userChoice;
      console.log('[PWA] User install choice:', choiceResult.outcome);

      if (choiceResult.outcome === 'accepted') {
        console.log('[PWA] User accepted installation prompt.');
      }
      deferredInstallPrompt = null;
    },

    /**
     * Network connectivity monitoring & toast alerts
     */
    initConnectivityMonitor() {
      window.addEventListener('offline', () => {
        console.warn('[PWA] Network disconnected. Running offline.');
        PWA.showToast('Network offline. Working from local cache.', 'warning');
      });

      window.addEventListener('online', () => {
        console.log('[PWA] Network reconnected.');
        PWA.showToast('Network connection restored.', 'success');
        PWA.checkForUpdates();
      });
    },

    /**
     * Lightweight non-intrusive terminal toast
     */
    showToast(message, type = 'info') {
      let toast = document.getElementById('pwa-network-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'pwa-network-toast';
        toast.className = 'fixed top-4 right-4 z-[9999] px-4 py-2 font-mono text-[11px] uppercase tracking-wider shadow-2xl transition-all duration-300 pointer-events-none transform translate-y-[-20px] opacity-0';
        document.body.appendChild(toast);
      }

      const colorClasses = type === 'warning'
        ? 'bg-[#1e1414] text-error border border-error/40'
        : type === 'success'
          ? 'bg-[#101b13] text-tertiary border border-tertiary/40'
          : 'bg-[#181818] text-primary border border-outline-variant/50';

      toast.className = `fixed top-4 right-4 z-[9999] px-4 py-2 font-mono text-[11px] uppercase tracking-wider shadow-2xl transition-all duration-300 pointer-events-none ${colorClasses}`;
      toast.textContent = message;

      // Animate in
      requestAnimationFrame(() => {
        toast.style.transform = 'translateY(0)';
        toast.style.opacity = '1';
      });

      // Animate out after 4 seconds
      setTimeout(() => {
        toast.style.transform = 'translateY(-20px)';
        toast.style.opacity = '0';
      }, 4000);
    }
  };

  // Expose to window
  window.ZeroNodePWA = PWA;

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => PWA.init());
  } else {
    PWA.init();
  }
})();

