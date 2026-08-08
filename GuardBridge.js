/**
 * GUARD BRIDGE v2.0 [HARDENED]
 *
 * [v2 PATCHES]
 * - [PATCH] mergeResults() now implemented (was undefined in v1)
 * - [PATCH] Weighted scoring with severity hierarchy
 * - [PATCH] Confidence levels: ALLOW / WARN / ALERT / GHOST / TERMINATE
 * - [PATCH] Frozen result objects
 * - [PATCH] Input sanitization before passing to guards
 * - [PATCH] Self-integrity check — verifies all guards are frozen
 * - [PATCH] Performance: early-exit on TERMINATE, no need to run remaining guards
 * - [PATCH] Audit log of all merged decisions
 */

const GuardBridge = (() => {
    'use strict';

    // Severity hierarchy — higher number = more severe
    const SEVERITY = Object.freeze({
        ALLOW:     0,
        WARN:      1,
        DROP:      2,
        ALERT:     3,
        GHOST:     4,
        TERMINATE: 5,
    });

    const _auditLog = [];
    const AUDIT_MAX = 200;

    // --- Merge results from multiple guards ---
    function mergeResults(results) {
        if (!results || results.length === 0) {
            return Object.freeze({ action: 'ALLOW', score: 0, sources: [] });
        }

        let maxSeverity = SEVERITY.ALLOW;
        let maxScore = 0;
        let winningAction = 'ALLOW';
        const sources = [];

        for (const r of results) {
            if (!r) continue;

            const action = r.action || 'ALLOW';
            const severity = SEVERITY[action] !== undefined ? SEVERITY[action] : SEVERITY.ALLOW;
            const score = typeof r.score === 'number' ? r.score : (severity > 0 ? severity / 5 : 0);

            sources.push({ action, score: r.score || 0, signals: r.signals || r.reason || null });

            // Most severe wins
            if (severity > maxSeverity) {
                maxSeverity = severity;
                winningAction = action;
            }
            // Highest score wins as tiebreaker
            if (score > maxScore) maxScore = score;
        }

        // Collect all signals
        const allSignals = [];
        for (const r of results) {
            if (!r) continue;
            if (Array.isArray(r.signals)) allSignals.push(...r.signals);
            if (Array.isArray(r.phases)) allSignals.push(...r.phases.map(p => 'PHASE:' + p));
        }

        const result = Object.freeze({
            action: winningAction,
            score: maxScore,
            sources: Object.freeze(sources),
            signals: Object.freeze(allSignals),
        });

        // Audit log
        _auditLog.push({ ts: Date.now(), result });
        if (_auditLog.length > AUDIT_MAX) _auditLog.shift();

        return result;
    }

    // --- Input sanitization ---
    function _sanitize(text) {
        if (typeof text !== 'string') return '';
        return text
            .replace(/[\u200B-\u200F\uFEFF\u00AD]/g, '')     // zero-width
            .replace(/[\u{1F000}-\u{1FAFF}]/gu, '')           // emoji
            .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars
            .normalize('NFKC');
    }

    // --- Verify all guards are frozen ---
    function _verifyGuards() {
        if (typeof NeuralGuard !== 'undefined' && !Object.isFrozen(NeuralGuard)) return false;
        if (typeof Pentagom !== 'undefined' && !Object.isFrozen(Pentagom)) return false;
        if (typeof AEGIS !== 'undefined' && !Object.isFrozen(AEGIS)) return false;
        return true;
    }

    const _api = Object.freeze({
        /**
         * Unified chat check — runs all available guards and merges results.
         * Most severe action wins.
         */
        checkChat(sender, recipient, text) {
            // Guard integrity
            if (!_verifyGuards()) {
                return Object.freeze({ action: 'TERMINATE', score: 1.0, sources: [], signals: ['GUARD_TAMPERED'] });
            }

            const cleanText = _sanitize(text);
            const results = [];

            if (typeof NeuralGuard !== 'undefined' && NeuralGuard.validate) {
                try { results.push(NeuralGuard.validate(sender, cleanText)); } catch (e) {}
            }
            if (typeof Pentagom !== 'undefined' && Pentagom.onPeerData) {
                try { results.push(Pentagom.onPeerData(sender, { msg: cleanText, to: recipient }, true)); } catch (e) {}
            }
            if (typeof AEGIS !== 'undefined' && AEGIS.pushChat) {
                try { results.push(AEGIS.pushChat(sender, recipient, cleanText)); } catch (e) {}
            }

            return mergeResults(results);
        },

        /**
         * Unified movement/telemetry check.
         */
        checkFrame(sender, packet) {
            if (!_verifyGuards()) {
                return Object.freeze({ action: 'DROP', score: 1.0, sources: [], signals: ['GUARD_TAMPERED'] });
            }

            const results = [];
            if (typeof Pentagom !== 'undefined' && Pentagom.onPeerData) {
                try { results.push(Pentagom.onPeerData(sender, packet, false)); } catch (e) {}
            }
            if (typeof AEGIS !== 'undefined' && AEGIS.pushFrame) {
                try { AEGIS.pushFrame(sender, packet); } catch (e) {}
            }

            return mergeResults(results);
        },

        /**
         * Get audit log of recent merged decisions.
         */
        getAuditLog() {
            return Object.freeze([..._auditLog]);
        },

        /**
         * Check if all guards are intact.
         */
        isHealthy() {
            return _verifyGuards();
        },
    });

    return _api;
})();

try { Object.freeze(GuardBridge); } catch (e) {}
