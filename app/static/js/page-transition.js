/**
 * ZeroNode - Page Transition Dot Loader
 * Handles seamless page transition feedback, link clicks, beforeunload, and bfcache.
 */
(function () {
    'use strict';

    let loader = null;
    let hideTimer = null;

    function getLoader() {
        if (!loader) {
            loader = document.getElementById('page-transition-loader');
        }
        return loader;
    }

    const Transition = {
        show() {
            clearTimeout(hideTimer);
            const el = getLoader();
            if (el) {
                el.classList.add('active');
            }
        },

        hide(delay = 80) {
            clearTimeout(hideTimer);
            hideTimer = setTimeout(() => {
                const el = getLoader();
                if (el) {
                    el.classList.remove('active');
                }
            }, delay);
        }
    };

    window.ZeroNodeTransition = Transition;

    // Smoothly fade out when page is ready
    if (document.readyState === 'complete') {
        Transition.hide(60);
    } else {
        window.addEventListener('load', () => Transition.hide(60));
        document.addEventListener('DOMContentLoaded', () => Transition.hide(60));
    }

    // Safety timeout: ensure loader never remains stuck on slow or aborted calls
    setTimeout(() => {
        Transition.hide(0);
    }, 2500);

    // Browser back/forward navigation (bfcache restore)
    window.addEventListener('pageshow', () => {
        Transition.hide(0);
    });

    // Native beforeunload event for tab refresh, back navigation, or submits
    window.addEventListener('beforeunload', () => {
        Transition.show();
    });

    // Intercept internal navigation link clicks for instantaneous feedback
    document.addEventListener('click', (e) => {
        const link = e.target.closest('a');
        if (!link) return;

        // Skip modified clicks (Ctrl/Cmd/Shift/Alt/middle-click)
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
            return;
        }

        // Skip blank targets or downloads
        if (link.target === '_blank' || link.hasAttribute('download')) {
            return;
        }

        const href = link.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) {
            return;
        }

        try {
            const targetUrl = new URL(link.href, window.location.origin);
            if (targetUrl.origin !== window.location.origin) return;

            // Skip file streaming and binary endpoints
            const path = targetUrl.pathname;
            if (path.includes('/download') || path.includes('/stream') || path.includes('/chunk') || path.includes('/api/file/')) {
                return;
            }

            // Same URL with hash anchor
            if (targetUrl.pathname === window.location.pathname && targetUrl.search === window.location.search && targetUrl.hash) {
                return;
            }

            // Trigger dot loader immediately
            Transition.show();
        } catch (err) {
            // Ignore parse errors
        }
    }, { capture: true });

})();

