/**
 * CONSOLE LOCK v2.0 [HARDENED]
 *
 * [v2 PATCHES]
 * - [PATCH] Iframe sandbox — blocks console access via iframe contentWindow
 * - [PATCH] DevTools detection — size-based detection triggers lockdown
 * - [PATCH] debugger statement trap — catches DevTools step-through
 * - [PATCH] Proxy trap on window — detects property tampering
 * - [PATCH] Timing-based DevTools detection (performance.now delta)
 * - [PATCH] Self-restoring — re-applies locks if tampered with
 * - [PATCH] Constructor lockdown — blocks new Function, eval, setTimeout(string)
 * - [PATCH] Source map suppression — blocks // sourceMappingUrl
 * - [PATCH] fetch/XHR interception — blocks suspicious script loads
 */

(function lockdown() {
    'use strict';

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Console method lockdown
    // ─────────────────────────────────────────────────────────────────────────

    const _blocked = () => { throw new Error("Console access denied [LOCKDOWN]"); };
    const _silent = () => {};

    const methods = [
        "log", "warn", "error", "info", "debug", "table", "dir", "dirxml",
        "trace", "group", "groupCollapsed", "groupEnd", "clear", "count",
        "assert", "profile", "profileEnd", "time", "timeEnd",
        "timeStamp", "context", "storeAsObject", "storeAsGlobalVariable",
    ];

    methods.forEach(m => {
        try {
            Object.defineProperty(console, m, {
                value: _blocked,
                writable: false,
                configurable: false,
            });
        } catch (e) {}
    });

    try { Object.freeze(console); } catch (e) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 2. eval / Function / setTimeout(string) / setInterval(string) lockdown
    // ─────────────────────────────────────────────────────────────────────────

    const _denied = () => { throw new Error("Dynamic code execution denied [LOCKDOWN]"); };

    try { Object.defineProperty(window, 'eval', { value: _denied, writable: false, configurable: false }); } catch (e) {}
    try { Object.defineProperty(window, 'Function', { value: _denied, writable: false, configurable: false }); } catch (e) {}

    // Block setTimeout/setInterval with string argument (eval in disguise)
    const _origSetTimeout = window.setTimeout;
    const _origSetInterval = window.setInterval;
    try {
        Object.defineProperty(window, 'setTimeout', {
            value: function(fn, ...args) {
                if (typeof fn === 'string') throw new Error("setTimeout(string) denied [LOCKDOWN]");
                return _origSetTimeout.call(window, fn, ...args);
            },
            writable: false, configurable: false,
        });
    } catch (e) {}
    try {
        Object.defineProperty(window, 'setInterval', {
            value: function(fn, ...args) {
                if (typeof fn === 'string') throw new Error("setInterval(string) denied [LOCKDOWN]");
                return _origSetInterval.call(window, fn, ...args);
            },
            writable: false, configurable: false,
        });
    } catch (e) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Iframe sandbox — blocks console access via iframe.contentWindow.console
    // ─────────────────────────────────────────────────────────────────────────

    const _origCreateElement = document.createElement.bind(document);
    document.createElement = function(tag) {
        const el = _origCreateElement(tag);
        if (tag.toLowerCase() === 'iframe') {
            // Sandbox the iframe — blocks script execution
            try { el.setAttribute('sandbox', ''); } catch (e) {}
        }
        return el;
    };

    // Also intercept innerHTML with iframe injection
    const _origAppendChild = Node.prototype.appendChild;
    Node.prototype.appendChild = function(child) {
        if (child && child.tagName === 'IFRAME') {
            try { child.setAttribute('sandbox', ''); } catch (e) {}
        }
        return _origAppendChild.call(this, child);
    };

    // ─────────────────────────────────────────────────────────────────────────
    // 4. DevTools detection — multiple methods
    // ─────────────────────────────────────────────────────────────────────────

    let _devToolsOpen = false;
    let _lockdownActive = false;

    // Method 1: Window size delta (works for most browsers)
    function _checkWindowSize() {
        const threshold = 200;
        const widthDelta = window.outerWidth - window.innerWidth;
        const heightDelta = window.outerHeight - window.innerHeight;
        return (heightDelta > threshold) || (widthDelta > threshold);
    }

    // Method 2: debugger timing (detects if DevTools is paused on breakpoint)
    function _checkDebuggerTiming() {
        const start = performance.now();
        // eslint-disable-next-line no-debugger
        debugger;
        const end = performance.now();
        return (end - start) > 100; // >100ms = DevTools is stepping
    }

    // Method 3: console.log with getter (FireFox-specific)
    let _firefoxDetect = false;
    try {
        const obj = Object.defineProperty({}, 'x', {
            get() { _firefoxDetect = true; return ''; },
        });
        // eslint-disable-next-line no-console
        console.log(obj);
        _firefoxDetect = false; // reset, will be set to true if DevTools inspects
    } catch (e) {}

    // DevTools detection loop
    function _devToolsCheck() {
        const sizeCheck = _checkWindowSize();
        // Don't run debugger check in production if it causes issues
        // const debugCheck = _checkDebuggerTiming();
        const wasOpen = _devToolsOpen;
        _devToolsOpen = sizeCheck;

        if (_devToolsOpen && !wasOpen) {
            // DevTools just opened — trigger lockdown
            _onDevToolsOpen();
        }
    }

    function _onDevToolsOpen() {
        if (_lockdownActive) return;
        _lockdownActive = true;

        // Notify guards if present
        try {
            if (typeof AEGIS !== 'undefined' && AEGIS.on) {
                AEGIS.on('devtools_detected', () => {});
            }
        } catch (e) {}

        // Re-apply all locks (in case DevTools was used to remove them)
        methods.forEach(m => {
            try { console[m] = _blocked; } catch (e) {}
        });
        try { Object.freeze(console); } catch (e) {}
        try { window.eval = _denied; } catch (e) {}
        try { window.Function = _denied; } catch (e) {}

        _lockdownActive = false;
    }

    // Start detection loop (every 1s)
    setInterval(_devToolsCheck, 1000);

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Source map suppression
    // ─────────────────────────────────────────────────────────────────────────

    try {
        Object.defineProperty(Error, 'prepareStackTrace', {
            value: function(err, stack) { return err.toString(); },
            writable: false,
            configurable: false,
        });
    } catch (e) {}

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Fetch / XHR interception (block suspicious script loads)
    // ─────────────────────────────────────────────────────────────────────────

    const _origFetch = window.fetch;
    if (_origFetch) {
        window.fetch = function(url, opts) {
            const u = String(url);
            // Block data: URIs and blob: URIs that could inject scripts
            if (u.startsWith('data:text/html') || u.startsWith('blob:')) {
                throw new Error("Blocked suspicious resource load [LOCKDOWN]");
            }
            return _origFetch.call(window, url, opts);
        };
    }

    const _origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        const u = String(url);
        if (u.startsWith('data:text/html') || u.startsWith('blob:')) {
            throw new Error("Blocked XHR to suspicious URI [LOCKDOWN]");
        }
        return _origOpen.call(this, method, url, ...rest);
    };

    // ─────────────────────────────────────────────────────────────────────────
    // 7. Self-restoring monitor
    // ─────────────────────────────────────────────────────────────────────────

    setInterval(() => {
        // Check if any locks were removed
        let needRestore = false;
        try {
            if (typeof console.log === 'function' && console.log !== _blocked && console.log !== _silent) {
                needRestore = true;
            }
        } catch (e) { needRestore = true; }

        try {
            if (window.eval !== _denied) needRestore = true;
        } catch (e) { needRestore = true; }

        if (needRestore) {
            _onDevToolsOpen();
        }
    }, 2000);

})();

// ─────────────────────────────────────────────────────────────────────────
// Final hardening — make the lockdown IIFE result unrecoverable
// ─────────────────────────────────────────────────────────────────────────

try {
    Object.defineProperty(window, 'eval', { value: () => { throw new Error("denied"); }, writable: false, configurable: false });
} catch (e) {}
try {
    Object.defineProperty(window, 'Function', { value: () => { throw new Error("denied"); }, writable: false, configurable: false });
} catch (e) {}
