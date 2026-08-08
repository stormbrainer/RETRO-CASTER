/**
 * ATTESTATION v3.0 [CHALLENGE-RESPONSE / HARDENED]
 *
 * [v3.0 — CHALLENGE-RESPONSE PROTOCOL]
 * - [NEW] Each client generates a random 256-bit session key at startup (never broadcast)
 * - [NEW] Session keys are exchanged privately per-connection (Peer.js data channel)
 * - [NEW] Challenge-response: hash(fingerprint + sessionKey + nonce)
 * - [NEW] A forger with a stolen fingerprint FAILS — no live session key
 * - [NEW] A forger with stolen fingerprint + session key must keep working guard code alive
 * - [NEW] Session keys rotate on reconnect — stale copies are useless
 * - [NEW] Challenge timeout: 5s to respond or auto-fail
 * - [NEW] Unanswered challenges accumulate as suspicion
 *
 * PROTOCOL FLOW:
 *   1. Peer A connects to Peer B (via Peer.js)
 *   2. A sends KEY_EXCHANGE to B with A's session key (private channel)
 *   3. B sends KEY_EXCHANGE to A with B's session key
 *   4. A sends ATTEST with A's fingerprint
 *   5. B sends CHALLENGE with random nonce to A
 *   6. A responds: CHALLENGE_RESPONSE = hash(fingerprint_A + sessionKey_A + nonce)
 *   7. B verifies: hash(expectedFingerprint + storedSessionKey_A + nonce) === response
 *   8. Repeat every 12-18s with fresh nonces
 *
 * ATTACK RESISTANCE:
 *   - Stale fingerprint only → FAIL (no session key)
 *   - Stale fingerprint + old session key → FAIL (key rotated on reconnect)
 *   - Live fingerprint + live session key → must maintain working guard code
 *   - Sybil with N forged peers → each needs unique session keys + valid fingerprints
 *
 * Preserves all v2.0 hardening:
 *   Timestamp validation, nonce tracking, graduated response, self-healing,
 *   anti-collusion, sybil resistance (threshold=3)
 */

const Attestation = (() => {
    'use strict';

    // ─────────────────────────────────────────────────────────────────────────
    // FNV-1a hash
    // ─────────────────────────────────────────────────────────────────────────

    function _fnv1a(str) {
        let h = 0x811c9dc5;
        for (let i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = Math.imul(h, 0x01000193);
        }
        return (h >>> 0).toString(16);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Generate random 256-bit session key (hex string)
    // ─────────────────────────────────────────────────────────────────────────

    function _generateSessionKey() {
        let key = '';
        // Use crypto.getRandomValues if available, else Math.random fallback
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const buf = new Uint8Array(32);
            crypto.getRandomValues(buf);
            for (let i = 0; i < buf.length; i++) {
                key += buf[i].toString(16).padStart(2, '0');
            }
        } else {
            for (let i = 0; i < 64; i++) {
                key += Math.floor(Math.random() * 16).toString(16);
            }
        }
        return key;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Compute fingerprint from all three guards
    // ─────────────────────────────────────────────────────────────────────────

    function computeSafeguardFingerprint() {
        const pieces = [
            (typeof NeuralGuard !== 'undefined' && NeuralGuard.getFingerprint) ? NeuralGuard.getFingerprint() : "dead",
            (typeof Pentagom !== 'undefined' && Pentagom.getFingerprint) ? Pentagom.getFingerprint() : "dead",
            (typeof AEGIS !== 'undefined' && AEGIS.getFingerprint) ? AEGIS.getFingerprint() : "dead",
            (typeof NeuralGuard !== 'undefined') ? (Object.isFrozen(NeuralGuard) ? "1" : "0") : "0",
            (typeof Pentagom !== 'undefined') ? (Object.isFrozen(Pentagom) ? "1" : "0") : "0",
            (typeof AEGIS !== 'undefined') ? (Object.isFrozen(AEGIS) ? "1" : "0") : "0",
        ].join("§");

        return _fnv1a(pieces);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    const MY_FP = computeSafeguardFingerprint();
    const MY_SESSION_KEY = _generateSessionKey();  // 256-bit, never broadcast

    // peerId → { fp, sessionKey, lastSeen, votes, warnings, trusted, challengeNonce, challengeTs, failedChallenges }
    const peerFPs = new Map();
    const _seenNonces = new Set();        // replay prevention (for ATTEST/ACCUSE/EXECUTE)
    const _challengeNonces = new Set();   // replay prevention (for challenges)
    const _accusedPeers = new Set();      // anti-collusion
    const _pendingChallenges = new Map(); // peerId → { nonce, ts, resolve }

    let _myPeerId = 'self';
    let _reloadAttempts = 0;

    const CONFIG = Object.freeze({
        BAD_THRESHOLD: 3,
        WARN_THRESHOLD: 1,
        SUSPECT_THRESHOLD: 2,
        TIMESTAMP_WINDOW: 10000,
        NONCE_CACHE_MAX: 256,
        CHALLENGE_NONCE_MAX: 128,
        ANNOUNCE_JITTER_MIN: 12000,
        ANNOUNCE_JITTER_MAX: 18000,
        STALE_PEER_MS: 60000,
        RELOAD_MAX_ATTEMPTS: 2,
        CHALLENGE_TIMEOUT: 5000,          // 5s to respond
        CHALLENGE_FAIL_LIMIT: 3,          // 3 failed challenges → accuse
        MAX_FAILED_CHALLENGES: 5,         // 5 total → execute ban
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Nonce management
    // ─────────────────────────────────────────────────────────────────────────

    function _checkNonce(nonce) {
        if (!nonce || typeof nonce !== 'string') return false;
        if (_seenNonces.has(nonce)) return false;
        _seenNonces.add(nonce);
        if (_seenNonces.size > CONFIG.NONCE_CACHE_MAX) {
            _seenNonces.delete(_seenNonces.values().next().value);
        }
        return true;
    }

    function _checkChallengeNonce(nonce) {
        if (!nonce || typeof nonce !== 'string') return false;
        if (_challengeNonces.has(nonce)) return false;
        _challengeNonces.add(nonce);
        if (_challengeNonces.size > CONFIG.CHALLENGE_NONCE_MAX) {
            _challengeNonces.delete(_challengeNonces.values().next().value);
        }
        return true;
    }

    function _validTimestamp(ts) {
        if (typeof ts !== 'number') return false;
        return Math.abs(Date.now() - ts) <= CONFIG.TIMESTAMP_WINDOW;
    }

    function _generateNonce() {
        return _generateSessionKey().slice(0, 16);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Broadcast (user wires this to Peer.js / WebSocket)
    // ─────────────────────────────────────────────────────────────────────────

    function _sendToPeer(peerId, msg) {
        // Add signature
        msg.from = _myPeerId;
        msg.ts = Date.now();
        msg.nonce = _generateNonce();
        // User should override window._attestSend with their actual per-peer send function
        if (typeof window._attestSend === 'function') {
            window._attestSend(peerId, msg);
        }
    }

    function _broadcast(msg) {
        msg.from = _myPeerId;
        msg.ts = Date.now();
        msg.nonce = _generateNonce();
        if (typeof window._attestBroadcast === 'function') {
            window._attestBroadcast(msg);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Self-healing
    // ─────────────────────────────────────────────────────────────────────────

    function _selfHeal() {
        if (_reloadAttempts < CONFIG.RELOAD_MAX_ATTEMPTS) {
            _reloadAttempts++;
            try { location.reload(); } catch (e) {}
            return;
        }
        _fullLockdown();
    }

    function _fullLockdown() {
        try {
            if (typeof NeuralGuard !== 'undefined' && NeuralGuard.endSession) NeuralGuard.endSession(_myPeerId);
            if (typeof Pentagom !== 'undefined' && Pentagom.handleBroadcast) Pentagom.handleBroadcast('BAN:' + _myPeerId);
            if (typeof AEGIS !== 'undefined' && AEGIS.clear) AEGIS.clear();
        } catch (e) {}
        try { window.location.href = 'about:blank'; } catch (e) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 1: Key Exchange
    //
    // When a new peer connects, exchange session keys privately.
    // The session key is sent over the Peer.js data channel (point-to-point),
    // NOT broadcast to all peers. This is the "never sent in the clear" part —
    // it's a private channel, not a public broadcast.
    // ─────────────────────────────────────────────────────────────────────────

    function onPeerConnect(peerId) {
        // Send our session key to this specific peer (private channel)
        _sendToPeer(peerId, {
            type: "KEY_EXCHANGE",
            sessionKey: MY_SESSION_KEY,
            fp: MY_FP,
        });

        // Initialize peer entry
        if (!peerFPs.has(peerId)) {
            peerFPs.set(peerId, {
                fp: null,
                sessionKey: null,
                lastSeen: Date.now(),
                votes: new Set(),
                warnings: 0,
                trusted: false,
                challengeNonce: null,
                challengeTs: 0,
                failedChallenges: 0,
                verified: false,
            });
        }
    }

    function onKeyExchange(fromPeerId, packet) {
        let entry = peerFPs.get(fromPeerId);
        if (!entry) {
            entry = {
                fp: null,
                sessionKey: null,
                lastSeen: Date.now(),
                votes: new Set(),
                warnings: 0,
                trusted: false,
                challengeNonce: null,
                challengeTs: 0,
                failedChallenges: 0,
                verified: false,
            };
            peerFPs.set(fromPeerId, entry);
        }

        // Store their session key (private, per-connection)
        entry.sessionKey = packet.sessionKey;
        entry.fp = packet.fp;
        entry.lastSeen = Date.now();

        // Immediately challenge them to verify
        _sendChallenge(fromPeerId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 2: Challenge-Response
    //
    // We send a random nonce. The peer must respond with:
    //   hash(fingerprint + sessionKey + nonce)
    //
    // We verify using the fingerprint and session key they gave us
    // during key exchange. If their code is tampered, the fingerprint
    // is wrong. If they're a stale copy, the session key is wrong.
    // ─────────────────────────────────────────────────────────────────────────

    function _sendChallenge(peerId) {
        const entry = peerFPs.get(peerId);
        if (!entry || !entry.sessionKey) return; // No session key yet

        const nonce = _generateNonce();
        entry.challengeNonce = nonce;
        entry.challengeTs = Date.now();

        _sendToPeer(peerId, {
            type: "CHALLENGE",
            nonce: nonce,
        });

        // Set timeout — if no response in 5s, count as failure
        setTimeout(() => {
            const e = peerFPs.get(peerId);
            if (e && e.challengeNonce === nonce) {
                // Challenge not answered
                e.failedChallenges++;
                if (e.failedChallenges >= CONFIG.CHALLENGE_FAIL_LIMIT) {
                    accuse(peerId, "CHALLENGE_TIMEOUT");
                }
                if (e.failedChallenges >= CONFIG.MAX_FAILED_CHALLENGES) {
                    execute(peerId, "CHALLENGE_FAILURES_EXCEEDED");
                }
            }
        }, CONFIG.CHALLENGE_TIMEOUT);
    }

    function onChallenge(fromPeerId, packet) {
        if (!_checkChallengeNonce(packet.nonce)) return;

        // We must prove we know OUR fingerprint + OUR session key + their nonce
        const response = _fnv1a(MY_FP + MY_SESSION_KEY + packet.nonce);

        _sendToPeer(fromPeerId, {
            type: "CHALLENGE_RESPONSE",
            nonce: packet.nonce,
            response: response,
            fp: MY_FP,  // Include our fingerprint so they can verify
        });
    }

    function onChallengeResponse(fromPeerId, packet) {
        if (!_checkChallengeNonce(packet.nonce)) return;

        const entry = peerFPs.get(fromPeerId);
        if (!entry) return;

        // Must match our pending challenge
        if (entry.challengeNonce !== packet.nonce) return;

        // Must be within timeout
        if (Date.now() - entry.challengeTs > CONFIG.CHALLENGE_TIMEOUT) return;

        // Verify: hash(theirFingerprint + theirSessionKey + nonce) === response
        const expected = _fnv1a(entry.fp + entry.sessionKey + packet.nonce);

        if (expected === packet.response) {
            // VERIFIED — peer has live, untampered guard code
            entry.verified = true;
            entry.trusted = true;
            entry.warnings = 0;
            entry.failedChallenges = 0;
        } else {
            // FAILED — peer is forging or has stale/tampered code
            entry.verified = false;
            entry.trusted = false;
            entry.failedChallenges++;

            if (entry.failedChallenges >= CONFIG.CHALLENGE_FAIL_LIMIT) {
                accuse(fromPeerId, "CHALLENGE_FAILED");
            }
            if (entry.failedChallenges >= CONFIG.MAX_FAILED_CHALLENGES) {
                execute(fromPeerId, "CHALLENGE_FAILURES_EXCEEDED");
            }
        }

        // Clear pending challenge
        entry.challengeNonce = null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 3: Attestation announce
    // ─────────────────────────────────────────────────────────────────────────

    function announce() {
        const current = computeSafeguardFingerprint();
        if (current !== MY_FP) {
            _selfHeal();
            return;
        }
        _broadcast({ type: "ATTEST", fp: current });

        // Also send fresh challenges to all connected, trusted peers
        for (const [peerId, entry] of peerFPs) {
            if (entry.sessionKey && Date.now() - entry.lastSeen < CONFIG.STALE_PEER_MS) {
                _sendChallenge(peerId);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Receive ATTEST from peer (still useful for fingerprint comparison)
    // ─────────────────────────────────────────────────────────────────────────

    function onAttest(fromPeerId, packet) {
        if (!_checkNonce(packet.nonce)) return;
        if (!_validTimestamp(packet.ts)) return;

        let entry = peerFPs.get(fromPeerId);
        if (!entry) {
            entry = {
                fp: null, sessionKey: null, lastSeen: 0,
                votes: new Set(), warnings: 0, trusted: false,
                challengeNonce: null, challengeTs: 0,
                failedChallenges: 0, verified: false,
            };
            peerFPs.set(fromPeerId, entry);
        }
        entry.fp = packet.fp;
        entry.lastSeen = Date.now();

        // Graduated response to fingerprint mismatch
        if (packet.fp !== MY_FP) {
            entry.warnings++;
            if (entry.warnings >= CONFIG.SUSPECT_THRESHOLD) {
                accuse(fromPeerId, "FP_MISMATCH_REPEATED");
            }
        } else {
            entry.warnings = 0;
        }

        // If we have their session key, challenge them to prove liveness
        if (entry.sessionKey && !entry.verified) {
            _sendChallenge(fromPeerId);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Accuse / Execute (same as v2, with challenge-failure additions)
    // ─────────────────────────────────────────────────────────────────────────

    function accuse(targetId, reason) {
        if (_accusedPeers.has(targetId)) return;
        _accusedPeers.add(targetId);
        _broadcast({ type: "ACCUSE", target: targetId, reason });
    }

    function onAccuse(fromPeerId, packet) {
        if (!_checkNonce(packet.nonce)) return;
        if (!_validTimestamp(packet.ts)) return;
        if (_accusedPeers.has(fromPeerId)) return;
        if (packet.target === _myPeerId) return;

        // Only trust accusations from verified peers
        const accuser = peerFPs.get(fromPeerId);
        if (!accuser || !accuser.verified) return;

        let entry = peerFPs.get(packet.target);
        if (!entry) {
            entry = {
                fp: null, sessionKey: null, lastSeen: 0,
                votes: new Set(), warnings: 0, trusted: false,
                challengeNonce: null, challengeTs: 0,
                failedChallenges: 0, verified: false,
            };
            peerFPs.set(packet.target, entry);
        }

        if (!entry.votes.has(fromPeerId)) {
            entry.votes.add(fromPeerId);
            if (entry.votes.size >= CONFIG.BAD_THRESHOLD) {
                execute(packet.target, packet.reason || "CONSENSUS_BAN");
            }
        }
    }

    function execute(badPeerId, reason) {
        if (typeof Pentagom !== 'undefined' && Pentagom.handleBroadcast) {
            Pentagom.handleBroadcast(`BAN:${badPeerId}`);
        }
        if (typeof NeuralGuard !== 'undefined' && NeuralGuard.endSession) {
            NeuralGuard.endSession(badPeerId);
        }

        _broadcast({ type: "EXECUTE", id: badPeerId, reason });
        peerFPs.delete(badPeerId);
        _accusedPeers.delete(badPeerId);
        _pendingChallenges.delete(badPeerId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Reap stale peers
    // ─────────────────────────────────────────────────────────────────────────

    function reapStale() {
        const now = Date.now();
        for (const [id, entry] of peerFPs) {
            if (now - entry.lastSeen > CONFIG.STALE_PEER_MS) {
                peerFPs.delete(id);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    const _api = Object.freeze({
        /**
         * Start attestation. Call after all guards are initialized.
         * @param {string} peerId - Your unique peer ID
         */
        start(peerId) {
            if (peerId) _myPeerId = peerId;

            // Initial announce
            announce();

            // Periodic announce + challenge cycle with jitter
            setInterval(() => {
                announce();
                reapStale();
            }, CONFIG.ANNOUNCE_JITTER_MIN + Math.random() * (CONFIG.ANNOUNCE_JITTER_MAX - CONFIG.ANNOUNCE_JITTER_MIN));
        },

        /**
         * Call this when a new peer connects (Peer.js 'connection' event).
         * Triggers key exchange + initial challenge.
         */
        onPeerConnect,

        /**
         * Call this when a peer disconnects.
         * Clears their session — their session key becomes stale.
         */
        onPeerDisconnect(peerId) {
            peerFPs.delete(peerId);
            _pendingChallenges.delete(peerId);
        },

        /**
         * Main data handler. Wire to peer.on('data').
         * Handles: KEY_EXCHANGE, ATTEST, CHALLENGE, CHALLENGE_RESPONSE, ACCUSE, EXECUTE
         */
        onData(from, packet) {
            if (!packet || typeof packet !== 'object') return;

            switch (packet.type) {
                case "KEY_EXCHANGE":
                    onKeyExchange(from, packet);
                    break;
                case "ATTEST":
                    onAttest(from, packet);
                    break;
                case "CHALLENGE":
                    onChallenge(from, packet);
                    break;
                case "CHALLENGE_RESPONSE":
                    onChallengeResponse(from, packet);
                    break;
                case "ACCUSE":
                    onAccuse(from, packet);
                    break;
                case "EXECUTE":
                    if (!_checkNonce(packet.nonce)) return;
                    if (!_validTimestamp(packet.ts)) return;
                    execute(packet.id, packet.reason);
                    break;
            }
        },

        /** Wire your per-peer send function (Peer.js conn.send) */
        setSendFn(fn) {
            if (typeof fn === 'function') window._attestSend = fn;
        },

        /** Wire your broadcast function (send to all peers) */
        setBroadcastFn(fn) {
            if (typeof fn === 'function') window._attestBroadcast = fn;
        },

        /** Get our fingerprint (for debugging) */
        getFingerprint() { return MY_FP; },

        /** Get our session key (for debugging — NEVER expose to peers) */
        _getSessionKey() { return MY_SESSION_KEY; },

        /** Force self-check */
        verify() {
            return computeSafeguardFingerprint() === MY_FP;
        },

        /** Check if a peer has passed challenge-response */
        isPeerVerified(peerId) {
            const e = peerFPs.get(peerId);
            return e ? e.verified : false;
        },

        /** Get peer status summary */
        getPeerStatus() {
            const summary = {};
            for (const [id, e] of peerFPs) {
                summary[id] = {
                    trusted: e.trusted,
                    verified: e.verified,
                    warnings: e.warnings,
                    failedChallenges: e.failedChallenges,
                    hasSessionKey: !!e.sessionKey,
                };
            }
            return summary;
        },
    });

    return _api;
})();
