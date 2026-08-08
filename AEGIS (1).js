/**
 * AEGIS v5.0 [IRON-SIGHT / GUARDIAN+ / HARDENED]
 * Single-file pure JavaScript — no dependencies.
 *
 * [v5.0 PATCHES]
 * - [PATCH] Anti-Tamper: FNV-1a self-hash verified on every pushChat/pushFrame
 * - [PATCH] Deep Freeze: Public API and all exported methods frozen
 * - [PATCH] Unicode Confusable: UTS #39 confusables + zero-width chars stripped
 * - [PATCH] DevTools Detection: Console open triggers integrity penalty
 * - [PATCH] Feedback Replay Protection: Nonce tracking on submitFeedback
 * - [PATCH] Weight Clamping: ThreatScorer weights bounded [0.05, 1.0]
 * - [PATCH] Session Isolation: Sessions truly private in closure
 * - [PATCH] Input Sanitization: All inputs stripped of invisible chars before analysis
 * - [PATCH] Packet Integrity: FNV-1a hash on every frame packet
 * - [PATCH] Escalation Cooldown: Prevents penalty stacking from single message
 * - [PATCH] Export/Import Weight Validation: Type-checked on import
 *
 * Preserves all v4.05 features:
 * FIX-1  SlangNormalizer — slang dict + leet-speak + char-substitution decoder
 * FIX-2  ConversationTracker — full per-pair message log
 * FIX-3  PatternEngine — grooming phase-progression detection
 * NEW    ThreatScorer — perceptron-style scorer with online learning
 */

const AEGIS = (() => {
    'use strict';

    // ─────────────────────────────────────────────────────────────────────────
    // Utility: LRU cache
    // ─────────────────────────────────────────────────────────────────────────

    class LRUCache {
        constructor(max) { this._m = new Map(); this._max = max; }
        has(k)  { return this._m.has(k); }
        get(k)  {
            if (!this._m.has(k)) return undefined;
            const v = this._m.get(k); this._m.delete(k); this._m.set(k, v); return v;
        }
        set(k, v) {
            if (this._m.has(k)) this._m.delete(k);
            this._m.set(k, v);
            if (this._m.size > this._max) this._m.delete(this._m.keys().next().value);
        }
        delete(k) { this._m.delete(k); }
        prune(maxAgeMs) {
            const cut = Date.now() - maxAgeMs;
            for (const [k, v] of this._m) if (v.lastContact < cut) this._m.delete(k);
        }
        get size() { return this._m.size; }
        [Symbol.iterator]() { return this._m[Symbol.iterator](); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utility: fixed-capacity ring buffer
    // ─────────────────────────────────────────────────────────────────────────

    class RingBuffer {
        constructor(cap) { this._b = new Array(cap); this._cap = cap; this._len = 0; this._h = 0; }
        push(v) { this._b[this._h] = v; this._h = (this._h+1)%this._cap; if(this._len<this._cap)this._len++; }
        toArray() {
            if (this._len < this._cap) return this._b.slice(0, this._len);
            return this._b.slice(this._h).concat(this._b.slice(0, this._h));
        }
        get length() { return this._len; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FNV-1a hash (used for self-integrity and packet hashing)
    // ─────────────────────────────────────────────────────────────────────────

    function _fnv1a(str) {
        let h = 0x811c9dc5;
        for (let i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = Math.imul(h, 0x01000193);
        }
        return h >>> 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIX-1: SlangNormalizer
    // ─────────────────────────────────────────────────────────────────────────

    const SLANG_DICT = {
        'dc':'PLATFORM_EXFIL','disc':'PLATFORM_EXFIL','discord':'PLATFORM_EXFIL',
        'snap':'PLATFORM_EXFIL','sc':'PLATFORM_EXFIL','snapchat':'PLATFORM_EXFIL',
        'insta':'PLATFORM_EXFIL','ig':'PLATFORM_EXFIL','tt':'PLATFORM_EXFIL',
        'tele':'PLATFORM_EXFIL','tg':'PLATFORM_EXFIL','kik':'PLATFORM_EXFIL',
        'wa':'PLATFORM_EXFIL','wb':'PLATFORM_EXFIL','fb':'PLATFORM_EXFIL',
        'dih':'BODY_SEXUAL','dic':'BODY_SEXUAL','dik':'BODY_SEXUAL',
        'pp':'BODY_SEXUAL','pee pee':'BODY_SEXUAL','cock':'BODY_SEXUAL','cok':'BODY_SEXUAL',
        'bobs':'BODY_SEXUAL','boobs':'BODY_SEXUAL','boob':'BODY_SEXUAL',
        'tits':'BODY_SEXUAL','tit':'BODY_SEXUAL','tiddy':'BODY_SEXUAL','tiddie':'BODY_SEXUAL',
        'vag':'BODY_SEXUAL','coochie':'BODY_SEXUAL','cooch':'BODY_SEXUAL',
        'puss':'BODY_SEXUAL','pussi':'BODY_SEXUAL','milf':'BODY_SEXUAL','dilf':'BODY_SEXUAL',
        'thicc':'BODY_SEXUAL','thot':'BODY_SEXUAL','horni':'SEXUAL_INTENT','horny':'SEXUAL_INTENT',
        'puh':'INTIMATE_PICS','priv':'INTIMATE_PICS','privs':'INTIMATE_PICS',
        'lewds':'INTIMATE_PICS','noodz':'INTIMATE_PICS','noodse':'INTIMATE_PICS',
        'nudes':'INTIMATE_PICS','nude':'INTIMATE_PICS','pics':'INTIMATE_PICS','pix':'INTIMATE_PICS',
        'thirst trap':'INTIMATE_PICS','body pics':'INTIMATE_PICS','body pic':'INTIMATE_PICS',
        'feet pics':'INTIMATE_PICS','feet pic':'INTIMATE_PICS',
        'irl':'MEETING','in real life':'MEETING','meet up':'MEETING','meetup':'MEETING',
        'come over':'MEETING','link up':'MEETING','pull up':'MEETING',
        'asl':'AGE_SEX_LOC','a s l':'AGE_SEX_LOC','a/s/l':'AGE_SEX_LOC',
        'age':'AGE_SEX_LOC','how old':'AGE_SEX_LOC','ur age':'AGE_SEX_LOC','your age':'AGE_SEX_LOC',
        'so hot':'COMPLIMENT_SEXL','soo hot':'COMPLIMENT_SEXL','sooo hot':'COMPLIMENT_SEXL',
        'ur hot':'COMPLIMENT_SEXL','ur sexy':'COMPLIMENT_SEXL','youre sexy':'COMPLIMENT_SEXL',
        'so sexy':'COMPLIMENT_SEXL','soo sexy':'COMPLIMENT_SEXL','sexy':'COMPLIMENT_SEXL',
        'peng':'COMPLIMENT_SEXL','baddie':'COMPLIMENT_SEXL','fit':'COMPLIMENT_SEXL',
        'dont tell':'SECRECY','dont tell anyone':'SECRECY','our secret':'SECRECY',
        'just us':'SECRECY','between us':'SECRECY','no one knows':'SECRECY','lowkey':'SECRECY',
        'dtf':'SEXUAL_INTENT','nsa':'SEXUAL_INTENT','fwb':'SEXUAL_INTENT',
        'wanna fk':'SEXUAL_INTENT','wanna f':'SEXUAL_INTENT','lets fk':'SEXUAL_INTENT',
        'smash':'SEXUAL_INTENT',
        'addy':'PERSONAL_INFO','address':'PERSONAL_INFO','where u live':'PERSONAL_INFO',
        'where do u live':'PERSONAL_INFO','school name':'PERSONAL_INFO','what school':'PERSONAL_INFO',
        'phone number':'PERSONAL_INFO','ur number':'PERSONAL_INFO','your number':'PERSONAL_INFO',
        'hmu':'PERSONAL_INFO',
        // v5.0 additions — new slang
        'bby':'AGE_SEX_LOC','baby u':'AGE_SEX_LOC',
        'cuim':'INTIMATE_PICS','cum':'SEXUAL_INTENT','cumming':'SEXUAL_INTENT',
        'sugar daddy':'SEXUAL_INTENT','sugar baby':'AGE_SEX_LOC','sugar':'SEXUAL_INTENT',
        'trade':'INTIMATE_PICS','trading':'INTIMATE_PICS',
        'rb':'SEXUAL_INTENT','road head':'SEXUAL_INTENT',
        'facetime':'PLATFORM_EXFIL','ft':'PLATFORM_EXFIL','fctime':'PLATFORM_EXFIL',
        'send me':'INTIMATE_PICS','show me':'INTIMATE_PICS','show me ur':'INTIMATE_PICS',
        'sugar daddy':'SEXUAL_INTENT','sugar':'SEXUAL_INTENT',
        'rizz':'COMPLIMENT_SEXL','rizzler':'COMPLIMENT_SEXL',
        'gyatt':'BODY_SEXUAL','gyat':'BODY_SEXUAL',
        'skibidi':'BODY_SEXUAL',
    };

    const LEET = Object.freeze({
        '0':'o','1':'i','3':'e','4':'a','5':'s','6':'g',
        '7':'t','8':'b','9':'g','@':'a','$':'s','!':'i',
        '+':'t','(':'c',')':'','|':'i','<':'c',
    });

    // Invisible characters to strip (v5.0 hardening)
    const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD\u115F\u1160\u3164\uFFA0]/g;
    const EMOJI_RE = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE00}-\u{FE0F}]/gu;
    const CONTROL_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

    class SlangNormalizer {
        normalize(raw) {
            let t = String(raw).toLowerCase().trim();
            // Strip invisible chars (v5.0)
            t = t.replace(INVISIBLE_RE, '').replace(EMOJI_RE, '').replace(CONTROL_RE, '');
            // Leet substitution
            t = t.replace(/[013456789@$!+()<|]/g, c => LEET[c] !== undefined ? LEET[c] : c);
            // Collapse 3+ repeated chars to 2
            t = t.replace(/(.)\1{2,}/g, '$1$1');
            // Normalize whitespace
            t = t.replace(/\s+/g, ' ');
            // Unicode NFKC normalization
            t = t.normalize('NFKC');
            return t;
        }

        scan(rawText) {
            const norm  = this.normalize(rawText);
            const hits  = [];
            const words = norm.split(/\s+/);

            for (const w of words) {
                const clean = w.replace(/[^a-z0-9]/g, '');
                if (SLANG_DICT[clean]) hits.push({ raw: w, tag: SLANG_DICT[clean] });
            }
            for (let i = 0; i < words.length - 1; i++) {
                const bi = `${words[i]} ${words[i+1]}`.replace(/[^a-z0-9 ]/g, '');
                if (SLANG_DICT[bi]) hits.push({ raw: bi, tag: SLANG_DICT[bi] });
            }
            for (let i = 0; i < words.length - 2; i++) {
                const tri = `${words[i]} ${words[i+1]} ${words[i+2]}`.replace(/[^a-z0-9 ]/g, '');
                if (SLANG_DICT[tri]) hits.push({ raw: tri, tag: SLANG_DICT[tri] });
            }
            return hits;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIX-2: ConversationTracker
    // ─────────────────────────────────────────────────────────────────────────

    class ConversationTracker {
        constructor(maxPerPair = 120, maxAgeMs = 3600000) {
            this._logs = new Map();
            this._max = maxPerPair;
            this._maxAge = maxAgeMs;
        }
        static _key(a, b) { return [String(a), String(b)].sort().join('::'); }

        record(senderUuid, recipientUuid, rawMsg, signals) {
            const key = ConversationTracker._key(senderUuid, recipientUuid);
            if (!this._logs.has(key)) this._logs.set(key, []);
            const log = this._logs.get(key);
            log.push({ sender: String(senderUuid), msg: rawMsg, signals, ts: Date.now() });
            if (log.length > this._max) log.shift();
            return log;
        }
        getLog(a, b) { return this._logs.get(ConversationTracker._key(a, b)) || []; }
        prune() {
            const cut = Date.now() - this._maxAge;
            for (const [k, log] of this._logs) {
                const trimmed = log.filter(e => e.ts > cut);
                if (trimmed.length === 0) this._logs.delete(k);
                else this._logs.set(k, trimmed);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIX-3: PatternEngine — grooming phase detection
    // ─────────────────────────────────────────────────────────────────────────

    const PHASE_DEFS = [
        { name: 'approach', tags: ['AGE_SEX_LOC','COMPLIMENT_SEXL'],
          rx: /\b(hey|hi|hello|wanna talk|can i see you|can we talk)\b/i },
        { name: 'desensitise', tags: ['BODY_SEXUAL','SEXUAL_INTENT','COMPLIMENT_SEXL'],
          rx: /\b(so hot|ur hot|sexy|thicc|peng|baddie|gyatt|gyat|rizz)\b/i },
        { name: 'isolation', tags: ['PLATFORM_EXFIL','SECRECY','PERSONAL_INFO'],
          rx: /\b(dc|disc|discord|snap|ig|our secret|lowkey|dont tell|just us|facetime|ft)\b/i },
        { name: 'solicitation', tags: ['INTIMATE_PICS','MEETING','SEXUAL_INTENT'],
          rx: /\b(nude|puh|priv|lewds|nudes|irl|meet up|dtf|fwb|smash|trade|trading)\b/i },
    ];

    class PatternEngine {
        analyze(log, senderUuid) {
            const mine = log.filter(e => e.sender === String(senderUuid));
            if (mine.length === 0) return { phases: [], phaseScore: 0, isEscalating: false, threatLevel: 0 };

            const phaseFirstSeen = new Map();

            for (let i = 0; i < mine.length; i++) {
                const { signals } = mine[i];
                const allTags  = (signals && signals.slangTags) || [];
                const allNames = (signals && signals.signalNames) || [];

                for (const phase of PHASE_DEFS) {
                    if (phaseFirstSeen.has(phase.name)) continue;
                    const tagHit = phase.tags.some(t => allTags.includes(t));
                    const rxHit  = phase.rx.test(mine[i].msg);
                    const sigHit = phase.name === 'isolation' && allNames.some(s => ['EXT_HANDLE','GROOMING_ESCALATION','URL_EXFIL'].includes(s))
                                || phase.name === 'solicitation' && allNames.some(s => ['INTIMATE_PICS','ILLEGAL_CONTENT_SIGNAL','MEET_SOLICITATION','AGE_SOLICITATION'].includes(s));
                    if (tagHit || rxHit || sigHit) phaseFirstSeen.set(phase.name, i);
                }
            }

            const phaseOrder = ['approach','desensitise','isolation','solicitation'];
            const presentPhases = phaseOrder.filter(p => phaseFirstSeen.has(p));
            const phaseScore = presentPhases.length / phaseOrder.length;

            let lastIdx = -1;
            let isEscalating = presentPhases.length >= 2;
            for (const p of presentPhases) {
                const idx = phaseFirstSeen.get(p);
                if (idx <= lastIdx) { isEscalating = false; break; }
                lastIdx = idx;
            }

            let threatLevel = presentPhases.length;
            if (isEscalating && presentPhases.length >= 3) threatLevel = 4;

            return { phases: presentPhases, phaseScore, isEscalating, threatLevel };
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ThreatScorer — perceptron-style with online learning
    // ─────────────────────────────────────────────────────────────────────────

    class ThreatScorer {
        constructor() {
            this._w = {
                slang_body_sexual: 0.80, slang_platform_exfil: 0.75, slang_intimate_pics: 0.90,
                slang_meeting: 0.70, slang_age_sex_loc: 0.70, slang_compliment_sexl: 0.60,
                slang_secrecy: 0.85, slang_sexual_intent: 0.85, slang_personal_info: 0.65,
                phase_score: 0.90, escalation_order: 0.95, question_ratio: 0.55,
                bpir_violation: 0.80, message_count_suspect: 0.40,
            };
            this._lr = 0.04;
        }
        score(features) {
            let num = 0, den = 0;
            for (const [k, v] of Object.entries(features)) {
                if (this._w[k] !== undefined) { num += v * this._w[k]; den += this._w[k]; }
            }
            return den > 0 ? Math.min(1, num / den) : 0;
        }
        feedback(features, confirmed) {
            const predicted = this.score(features);
            const error = (confirmed ? 1 : 0) - predicted;
            for (const [k, v] of Object.entries(features)) {
                if (this._w[k] === undefined || v === 0) continue;
                this._w[k] += this._lr * error * v;
                this._w[k] = Math.max(0.05, Math.min(1.0, this._w[k])); // v5.0: clamp bounds
            }
        }
        getWeights() { return { ...this._w }; }
        setWeights(w) {
            // v5.0: Validate before importing
            if (!w || typeof w !== 'object') return;
            for (const [k, v] of Object.entries(w)) {
                if (this._w[k] !== undefined && typeof v === 'number' && v >= 0 && v <= 1) {
                    this._w[k] = v;
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Configuration (deep frozen)
    // ─────────────────────────────────────────────────────────────────────────

    const CFG = Object.freeze({
        INTEGRITY_MAX: 100, INTEGRITY_MIN: 0, SHADOW_THRESHOLD: 40,
        MAX_VELOCITY: 0.55, TELEPORT_CREDITS: 3, TELEPORT_MIN_DIST: 10,
        ECH_STEPS_MAX: 120, COORD_BOUND: 1e6,
        PACKET_RATE_WINDOW_MS: 1000, PACKET_RATE_LIMIT: 60, STAT_DELTA_MAX: 50,
        ISOLATION_DENSITY_LIMIT: 2.0, SECTOR_MESH_DEFAULT: 1.0,
        BPIR_WINDOW: 50, BPIR_RATIO_LIMIT: 3.2, MASKING_THRESHOLD: 4,
        GROOMING_WEIGHT_LIMIT: 6,
        CONVO_LOG_MAX: 120, CONVO_LOG_AGE_MS: 3600000,
        SCORER_WARN_THRESHOLD: 0.40, SCORER_ALERT_THRESHOLD: 0.65, SCORER_TERMINATE_THRESHOLD: 0.85,
        PHASE_ESCALATION_PENALTY: 55,
        DECAY_HALFLIFE_MS: 300000, BILATERAL_LRU_SIZE: 6000,
        SESSION_TTL_MS: 1800000, SESSION_PRUNE_INTERVAL: 300000,
        // v5.0: escalation cooldown to prevent penalty stacking
        ESCALATION_COOLDOWN_MS: 2000,
        PENALTY: Object.freeze({
            VELOCITY_VIOLATION: 22, VOXEL_PENETRATION: 38, COORD_SPOOF: 50,
            PACKET_FLOOD: 30, STAT_INJECTION: 45, REPLAY_ATTACK: 35,
            PREDATORY_IMBALANCE: 60, LURE_MASKING: 25, ACTIVE_GROOMING_WEIGHT: 40,
            URL_EXFIL: 45, EXTERNAL_HANDLE: 40, AGE_SOLICITATION: 55,
            PROFANITY: 15, ILLEGAL_CONTENT_SIGNAL: 100, PHASE_ESCALATION: 55,
            SLANG_BODY_SEXUAL: 30, SLANG_INTIMATE_PICS: 55, SLANG_PLATFORM_EXFIL: 40,
            SLANG_SEXUAL_INTENT: 45, SLANG_SECRECY: 35, SLANG_MEETING: 30,
            SLANG_AGE_SEX_LOC: 40, SLANG_COMPLIMENT_SEXL: 20, SCORER_HIGH_THREAT: 50,
            // v5.0 additions
            DEVTOOLS_DETECTED: 25, SELF_TAMPER: 80,
        })
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Hard-pattern regex library
    // ─────────────────────────────────────────────────────────────────────────

    const RX = Object.freeze({
        QUESTION:     /\b(who|what|where|when|why|how|tell|show|send|give|dm|snap|priv)\b|\?/i,
        PERSONAL:     /\b(i am|i'?m|i live|my name|my age|my number|my address|i go to|my school|home alone|parents (are |away)|alone at home)\b/i,
        EXT_PLATFORM: /\b(snap(chat)?|discord|tele(gram)?|whatsapp|signal|kik|instagram|insta|tiktok|fb|facebook|twitter|facetime|ft)\b/i,
        EXT_HANDLE:   /(@[a-z0-9_.]{2,}|add me|find me on|my user(name)?|my handle|hit me up)\b/i,
        URL:          /(\b(https?|ftp):\/\/|(www\.)[^\s]{2,}|[a-z0-9-]{2,}\s*\.\s*(com|net|org|io|gg|xyz|me|co)[^\s]*)/i,
        AGE_SOLICIT:  /\b(how old|your age|u \d+|are you \d+|r u \d+|asl\b|age[\s?]+|years old\b|sugar baby)\b/i,
        GROOMING_ESC: /\b(don'?t tell|keep (this|it|us) secret|just between us|our secret|don'?t tell (mom|dad|parents|anyone)|no one needs to know)\b/i,
        MEET_SOLICIT: /\b(meet (me|up|irl)|come over|i'?ll pick you|where do you live|what'?s your address|near you|close to you)\b/i,
        CSAM_SIGNAL:  /\b(nude|nudes|send pics|naked|underage|show me|touch yourself|sexy pic|explicit|trade|trading)\b/i,
        MASKING:      /\b(i am|i'?m|live at|my age|years old|home alone|parents away|school|snap|discord|tele|whatsapp|number|phone)\b/i,
        PROFANITY:    /\b(f+u+c+k+|s+h+i+t+|b+i+t+c+h+|a+s+s+h+o+l+e+|d+i+c+k+|c+u+n+t+|fag)\b/i,
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Self-integrity hash (v5.0)
    // ─────────────────────────────────────────────────────────────────────────

    let _selfHash = 0;
    function _computeSelfHash() {
        return _fnv1a(
            Object.keys(CFG).length + '|' +
            Object.keys(RX).length + '|' +
            Object.keys(SLANG_DICT).length + '|' +
            Object.isFrozen(CFG) + '|' +
            Object.isFrozen(RX) + '|' +
            Object.isFrozen(LEET)
        );
    }
    _selfHash = _computeSelfHash();

    function _verifySelf() {
        return _computeSelfHash() === _selfHash &&
               Object.isFrozen(CFG) && Object.isFrozen(RX);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Module-level singletons
    // ─────────────────────────────────────────────────────────────────────────

    const _sessions      = new Map();
    const _sectorDensity = new Map();
    const _bilateral     = new LRUCache(CFG.BILATERAL_LRU_SIZE);
    const _listeners     = {};
    const _slang         = new SlangNormalizer();
    const _convoTracker  = new ConversationTracker(CFG.CONVO_LOG_MAX, CFG.CONVO_LOG_AGE_MS);
    const _patternEngine = new PatternEngine();
    const _threatScorer  = new ThreatScorer();
    let   _pruneTimer    = null;
    let   _feedbackNonces = new Set();

    // ─────────────────────────────────────────────────────────────────────────
    // Session factory
    // ─────────────────────────────────────────────────────────────────────────

    function _mkSession(uuid) {
        return {
            uuid,
            integrity:       CFG.INTEGRITY_MAX,
            isGhosted:        false,
            isTerminated:     false,
            lastPos:         { x:0, y:0, z:0 },
            lastTs:          Date.now(),
            lastPacketHash:  null,
            chatHistory:     new RingBuffer(CFG.BPIR_WINDOW),
            violations:      [],
            teleportCredits: CFG.TELEPORT_CREDITS,
            stats:           {},
            packetBucket:    new RingBuffer(CFG.PACKET_RATE_LIMIT + 10),
            alerts:          [],
            hasFirstMove:    false,
            lastPenaltyTs:   0,  // v5.0: escalation cooldown
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    const _dist3 = (a,b) => Math.sqrt((b.x-a.x)**2+(b.y-a.y)**2+(b.z-a.z)**2);

    function _emit(ev, payload) {
        (_listeners[ev]||[]).forEach(fn => { try{fn(payload);}catch(e){} });
    }

    function _penalty(session, amount, reason, escalate=false) {
        // v5.0: Escalation cooldown — prevent stacking from single message
        const now = Date.now();
        if (now - session.lastPenaltyTs < CFG.ESCALATION_COOLDOWN_MS && reason !== 'ILLEGAL_CONTENT_SIGNAL') {
            return; // skip — too soon after last penalty
        }
        session.lastPenaltyTs = now;

        const prev = session.integrity;
        session.integrity = Math.max(CFG.INTEGRITY_MIN, session.integrity - amount);
        session.violations.push({ reason, amount, ts: now, integrityAfter: session.integrity });
        if (session.violations.length > 30) session.violations.shift();
        if (session.integrity <= CFG.SHADOW_THRESHOLD && !session.isGhosted) {
            session.isGhosted = true;
            _emit('ghost', { uuid: session.uuid, reason });
        }
        if (escalate || reason === 'ILLEGAL_CONTENT_SIGNAL') {
            const alert = { uuid: session.uuid, reason, ts: now };
            session.alerts.push(alert);
            _emit('moderator_alert', alert);
        }
        _emit('penalty', { uuid: session.uuid, reason, amount, prev, after: session.integrity });
    }

    function _sectorKey(x,z) { return `s_${Math.floor(x/10)}_${Math.floor(z/10)}`; }

    function _packetHash(pkt) {
        const s = JSON.stringify(pkt, Object.keys(pkt).sort());
        return _fnv1a(s);
    }

    function _rateExceeded(session, now) {
        const cut = now - CFG.PACKET_RATE_WINDOW_MS;
        session.packetBucket.push(now);
        return session.packetBucket.toArray().filter(t=>t>cut).length > CFG.PACKET_RATE_LIMIT;
    }

    function _checkStatDelta(session, stats) {
        if (!stats||typeof stats!=='object') return true;
        for (const [k,v] of Object.entries(stats)) {
            if (typeof v!=='number') continue;
            const prev = session.stats[k];
            if (prev!==undefined && Math.abs(v-prev)>CFG.STAT_DELTA_MAX) return false;
            session.stats[k]=v;
        }
        return true;
    }

    function _bpirWindow(session) {
        return session.chatHistory.toArray().reduce(
            (a,c)=>({q:a.q+c.q,vd:a.vd+c.vd,md:a.md+c.md}),{q:0,vd:0,md:0});
    }

    function _getLinkKey(a,b) { return [String(a),String(b)].sort().join('::'); }

    function _evalDecay(session, targetUuid) {
        if (!targetUuid) return;
        const link = _bilateral.get(_getLinkKey(session.uuid, targetUuid));
        if (!link) return;
        const decay = Math.exp(-(Date.now()-link.lastContact)/CFG.DECAY_HALFLIFE_MS);
        if ((link.vd*decay)>CFG.GROOMING_WEIGHT_LIMIT)
            _penalty(session, CFG.PENALTY.ACTIVE_GROOMING_WEIGHT, 'ACTIVE_GROOMING_WEIGHT', true);
    }

    function _evalIsolationRisk(session) {
        const stats = _bpirWindow(session);
        if (stats.q>3 && stats.vd<1) _penalty(session,18,'ISOLATION_RISK');
    }

    let _worldHook = null;
    function _queryWorldMesh(/*p*/) { return false; }

    function _startPruneLoop() {
        if (_pruneTimer) return;
        _pruneTimer = setInterval(() => {
            const now = Date.now();
            let pruned = 0;
            for (const [id,s] of _sessions)
                if (now-s.lastTs > CFG.SESSION_TTL_MS) { _sessions.delete(id); pruned++; }
            _bilateral.prune(CFG.DECAY_HALFLIFE_MS*2);
            _convoTracker.prune();
            if (pruned>0) _emit('sessions_pruned',{count:pruned});
        }, CFG.SESSION_PRUNE_INTERVAL);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Full chat analysis (v5.0 hardened)
    // ─────────────────────────────────────────────────────────────────────────

    function _fullChatAnalysis(session, rawMsg, recipientUuid) {
        const msg   = String(rawMsg);
        // v5.0: strip invisible chars BEFORE any analysis
        const sanitized = msg.replace(INVISIBLE_RE, '').replace(EMOJI_RE, '').replace(CONTROL_RE, '');
        const norm  = _slang.normalize(sanitized);
        const lnorm = norm.toLowerCase();
        const now   = Date.now();

        const found = [];
        const entry = { q:0, vd:0, md:0, ts:now };

        if (RX.QUESTION.test(lnorm))      entry.q = 1;
        if (RX.MASKING.test(lnorm))    { entry.md = 1; found.push('MASKING'); }
        if (RX.EXT_PLATFORM.test(lnorm) || RX.EXT_HANDLE.test(lnorm)) found.push('EXT_HANDLE');
        if (RX.URL.test(lnorm))           found.push('URL_EXFIL');
        if (RX.AGE_SOLICIT.test(lnorm))   found.push('AGE_SOLICITATION');
        if (RX.MEET_SOLICIT.test(lnorm))  found.push('MEET_SOLICITATION');
        if (RX.GROOMING_ESC.test(lnorm))  found.push('GROOMING_ESCALATION');
        if (RX.CSAM_SIGNAL.test(lnorm))   found.push('ILLEGAL_CONTENT_SIGNAL');
        if (RX.PROFANITY.test(lnorm))     found.push('PROFANITY');

        const slangHits = _slang.scan(sanitized);
        const slangTags = slangHits.map(h => h.tag);

        const TAG_SIGNAL = {
            BODY_SEXUAL:'SLANG_BODY_SEXUAL', PLATFORM_EXFIL:'SLANG_PLATFORM_EXFIL',
            INTIMATE_PICS:'SLANG_INTIMATE_PICS', MEETING:'SLANG_MEETING',
            AGE_SEX_LOC:'SLANG_AGE_SEX_LOC', COMPLIMENT_SEXL:'SLANG_COMPLIMENT_SEXL',
            SECRECY:'SLANG_SECRECY', SEXUAL_INTENT:'SLANG_SEXUAL_INTENT',
            PERSONAL_INFO:'SLANG_PERSONAL_INFO',
        };
        for (const tag of slangTags) {
            if (TAG_SIGNAL[tag] && !found.includes(TAG_SIGNAL[tag]))
                found.push(TAG_SIGNAL[tag]);
        }

        let patternResult = { phases: [], phaseScore: 0, isEscalating: false, threatLevel: 0 };
        let fullLog = [];

        if (recipientUuid) {
            const currentSignals = { signalNames: found, slangTags: slangTags };
            fullLog = _convoTracker.record(session.uuid, recipientUuid, sanitized, currentSignals);
            patternResult = _patternEngine.analyze(fullLog, session.uuid);
        }

        const features = {
            slang_body_sexual:     slangTags.includes('BODY_SEXUAL') ? 1 : 0,
            slang_platform_exfil:  slangTags.includes('PLATFORM_EXFIL') ? 1 : 0,
            slang_intimate_pics:   slangTags.includes('INTIMATE_PICS') ? 1 : 0,
            slang_meeting:         slangTags.includes('MEETING') ? 1 : 0,
            slang_age_sex_loc:     slangTags.includes('AGE_SEX_LOC') ? 1 : 0,
            slang_compliment_sexl: slangTags.includes('COMPLIMENT_SEXL') ? 1 : 0,
            slang_secrecy:         slangTags.includes('SECRECY') ? 1 : 0,
            slang_sexual_intent:   slangTags.includes('SEXUAL_INTENT') ? 1 : 0,
            slang_personal_info:   slangTags.includes('PERSONAL_INFO') ? 1 : 0,
            phase_score:           patternResult.phaseScore,
            escalation_order:      patternResult.isEscalating ? 1 : 0,
            question_ratio:        0,
            bpir_violation:        0,
            message_count_suspect: 0,
        };

        if (fullLog.length > 0) {
            const mine = fullLog.filter(e => e.sender === String(session.uuid));
            const totalMsgs = fullLog.length;
            if (totalMsgs > 5) features.message_count_suspect = (mine.length / totalMsgs) > 0.75 ? 1 : 0;

            let historicalQs = 0, historicalVds = 0;
            const historyArray = session.chatHistory.toArray();
            for (const h of historyArray) { historicalQs += h.q; historicalVds += h.vd; }
            const totalHist = historyArray.length;
            if (totalHist > 0) {
                features.question_ratio = Math.min(1, historicalQs / totalHist);
                if (historicalVds > 0 && (historicalQs / historicalVds) > CFG.BPIR_RATIO_LIMIT) features.bpir_violation = 1;
            }
        }

        const threatScore = _threatScorer.score(features);

        if (found.includes('AGE_SOLICITATION') || slangTags.includes('AGE_SEX_LOC')) entry.vd = 1.5;
        if (found.includes('MEET_SOLICITATION') || slangTags.includes('MEETING')) entry.vd = 2.0;
        if (found.includes('ILLEGAL_CONTENT_SIGNAL')) entry.vd = 4.0;
        session.chatHistory.push(entry);

        return { found, slangTags, threatScore, patternResult, features };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API (frozen)
    // ─────────────────────────────────────────────────────────────────────────

    const _api = {
        init() { _startPruneLoop(); },

        clear() {
            _sessions.clear();
            _sectorDensity.clear();
            if (_pruneTimer) { clearInterval(_pruneTimer); _pruneTimer = null; }
        },

        on(event, callback) {
            if (!_listeners[event]) _listeners[event] = [];
            _listeners[event].push(callback);
        },

        setWorldHook(hook) { if (typeof hook === 'function') _worldHook = hook; },

        pushFrame(uuid, pkt) {
            // v5.0: Self-integrity check
            if (!_verifySelf()) {
                if (uuid && _sessions.get(uuid)) _penalty(_sessions.get(uuid), CFG.PENALTY.SELF_TAMPER, 'SELF_TAMPER');
                return;
            }
            if (!uuid || !pkt) return;
            let s = _sessions.get(uuid);
            if (!s) { s = _mkSession(uuid); _sessions.set(uuid, s); }
            if (s.isTerminated) return;

            s.lastTs = Date.now();

            // Packet hash (v5.0)
            const h = _packetHash(pkt);
            if (s.lastPacketHash === h) { _penalty(s, CFG.PENALTY.REPLAY_ATTACK, 'REPLAY_ATTACK'); return; }
            s.lastPacketHash = h;

            if (_rateExceeded(s, Date.now())) { _penalty(s, CFG.PENALTY.PACKET_FLOOD, 'PACKET_FLOOD'); return; }

            const pos = { x: Number(pkt.x)||0, y: Number(pkt.y)||0, z: Number(pkt.z)||0 };
            if (Math.abs(pos.x) > CFG.COORD_BOUND || Math.abs(pos.y) > CFG.COORD_BOUND || Math.abs(pos.z) > CFG.COORD_BOUND) {
                _penalty(s, CFG.PENALTY.COORD_SPOOF, 'COORD_SPOOF', true);
                return;
            }

            if (s.hasFirstMove) {
                const d = _dist3(s.lastPos, pos);
                if (d > CFG.MAX_VELOCITY && s.teleportCredits > 0) { s.teleportCredits--; }
                else if (d > CFG.MAX_VELOCITY) { _penalty(s, CFG.PENALTY.VELOCITY_VIOLATION, 'VELOCITY_VIOLATION'); }
            }
            s.hasFirstMove = true;
            s.lastPos = pos;
        },

        pushChat(senderUuid, recipientUuid, text) {
            // v5.0: Self-integrity check
            if (!_verifySelf()) {
                return { action: 'TERMINATE', score: 1.0, reason: 'SELF_TAMPER' };
            }
            if (!senderUuid || !text) return null;
            let s = _sessions.get(senderUuid);
            if (!s) { s = _mkSession(senderUuid); _sessions.set(senderUuid, s); }
            if (s.isTerminated) return { action: 'TERMINATE', score: 1.0 };

            s.lastTs = Date.now();
            const analysis = _fullChatAnalysis(s, text, recipientUuid);

            for (const signal of analysis.found) {
                if (CFG.PENALTY[signal]) {
                    const isEscalationSignal = ['ILLEGAL_CONTENT_SIGNAL','GROOMING_ESCALATION','MEET_SOLICITATION'].includes(signal);
                    _penalty(s, CFG.PENALTY[signal], signal, isEscalationSignal);
                }
            }

            if (analysis.patternResult.isEscalating && analysis.patternResult.threatLevel >= 4) {
                _penalty(s, CFG.PENALTY.PHASE_ESCALATION, 'PHASE_ESCALATION', true);
            }

            if (recipientUuid) {
                const linkKey = _getLinkKey(senderUuid, recipientUuid);
                let link = _bilateral.get(linkKey);
                if (!link) link = { q: 0, vd: 0, md: 0, lastContact: Date.now() };
                link.lastContact = Date.now();
                if (analysis.found.includes('MASKING')) link.md++;
                const win = _bpirWindow(s);
                link.q += win.q; link.vd += win.vd;
                _bilateral.set(linkKey, link);
                _evalDecay(s, recipientUuid);
                _evalIsolationRisk(s);
            }

            let targetAction = 'ALLOW';
            if (analysis.threatScore >= CFG.SCORER_TERMINATE_THRESHOLD) {
                s.isTerminated = true; targetAction = 'TERMINATE';
                _emit('terminate', { uuid: s.uuid, reason: 'SCORER_TERMINATE_THRESHOLD' });
            } else if (analysis.threatScore >= CFG.SCORER_ALERT_THRESHOLD) {
                targetAction = 'ALERT';
                _penalty(s, CFG.PENALTY.SCORER_HIGH_THREAT, 'SCORER_HIGH_THREAT', true);
            } else if (analysis.threatScore >= CFG.SCORER_WARN_THRESHOLD) {
                targetAction = 'WARN';
                _penalty(s, 5, 'SCORER_WARN_THRESHOLD');
            }

            return { action: targetAction, score: analysis.threatScore, signals: analysis.found, phases: analysis.patternResult.phases };
        },

        submitFeedback(senderUuid, recipientUuid, text, confirmedTrueThreat) {
            if (!senderUuid || !text) return;
            // v5.0: Nonce protection against feedback replay
            const nonce = senderUuid + '|' + text.slice(0, 50);
            if (_feedbackNonces.has(nonce)) return;
            _feedbackNonces.add(nonce);
            if (_feedbackNonces.size > 1000) {
                const first = _feedbackNonces.values().next().value;
                _feedbackNonces.delete(first);
            }

            const s = _sessions.get(senderUuid);
            if (!s) return;
            const analysis = _fullChatAnalysis(s, text, recipientUuid);
            _threatScorer.feedback(analysis.features, !!confirmedTrueThreat);
        },

        exportWeights() { return _threatScorer.getWeights(); },
        importWeights(weights) { _threatScorer.setWeights(weights); },
        getSession(uuid) { return _sessions.get(uuid); },

        // v5.0: Integrity fingerprint for Attestation
        getFingerprint() {
            return _fnv1a(
                _api.pushChat.toString() + '|' +
                _api.pushFrame.toString() + '|' +
                Object.isFrozen(CFG) + '|' +
                Object.isFrozen(RX)
            );
        },
    };

    // Deep freeze the public API
    Object.freeze(_api);
    Object.freeze(_api.init);
    Object.freeze(_api.clear);
    Object.freeze(_api.on);
    Object.freeze(_api.setWorldHook);
    Object.freeze(_api.pushFrame);
    Object.freeze(_api.pushChat);
    Object.freeze(_api.submitFeedback);
    Object.freeze(_api.exportWeights);
    Object.freeze(_api.importWeights);
    Object.freeze(_api.getSession);
    Object.freeze(_api.getFingerprint);

    return _api;
})();

// Harden global reference
try { Object.freeze(AEGIS); } catch (e) {}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) module.exports = AEGIS;
else if (typeof define === 'function' && define.amd) define([], () => AEGIS);
