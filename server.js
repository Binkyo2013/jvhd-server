'use strict';
// ============================================================================
// JVHD AUTH SERVER — Device Binding + Challenge/Response (Yc11)
// Data source: OneDrive READ ONLY (replaces JSONBin)
// ============================================================================
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

// ---- OneDrive share URLs (READ ONLY) ----------------------------------------
// These can be overridden via environment variables on Render.
const ONEDRIVE_MEMBER_URL = process.env.ONEDRIVE_MEMBER_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQBDC0QATqfRR4ROzrev8HbZAYl9Ie1vzNapxj7CTMPX08g?e=coaE1V';
const ONEDRIVE_HASH4_URL = process.env.ONEDRIVE_HASH4_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQDDyKOWH_aLS40GJvPdPhK9AWjPGlotl_cqrjuD8fBGHtY?e=Sbe5u2';
const ONEDRIVE_BINDING_URL = process.env.ONEDRIVE_BINDING_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQBWqH6cfl_RSKUFv8u1A-8SAWurCQjKeOvM9hNGUXtxn_E?e=lpaSYb';
const ONEDRIVE_TARGETURL_URL = process.env.ONEDRIVE_TARGETURL_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQBzWVFIXQRfRY5w1af6pNjxAYwIHtGQEk_OX2EV-_i_XRw?e=K8wJkD';

const ONEDRIVE_TTL_MS = parseInt(process.env.ONEDRIVE_TTL_MS || '60000', 10);
const ALLOWLIST_STATIC = process.env.ALLOWLIST_STATIC || '';

const CHALLENGE_TTL_MS = parseInt(process.env.CHALLENGE_TTL_MS || '120000', 10);
const MAX_BODY = parseInt(process.env.MAX_BODY || '16384', 10);
const REMOTE_MAX_BODY = parseInt(process.env.REMOTE_MAX_BODY || String(MAX_BODY * 100), 10);
const BINDING_LOAD_ATTEMPTS = parseInt(process.env.BINDING_LOAD_ATTEMPTS || '5', 10);

const CRYPTO_HASH_RE = /^[0-9a-f]{64}$/;
const SPKI_P256 = Buffer.from(
    '3059301306072a8648ce3d020106082a8648ce3d030107034200',
    'hex'
);

// ---- ECDSA P-256 ------------------------------------------------------------
function pubFromRaw(kB64) {
    try {
        const raw = Buffer.from(String(kB64), 'base64');
        if (raw.length !== 65 || raw[0] !== 4) return null;
        return crypto.createPublicKey({
            key: Buffer.concat([SPKI_P256, raw]),
            format: 'der',
            type: 'spki',
        });
    } catch (e) {
        return null;
    }
}

function verifySig(keyObj, dataBuf, sigB64) {
    try {
        return crypto.createVerify('SHA256')
            .update(dataBuf)
            .verify(keyObj, Buffer.from(String(sigB64), 'base64'));
    } catch (e) {
        return false;
    }
}

// ---- OneDrive fetcher -------------------------------------------------------

// Convert 1drv.ms share URL to OneDrive API download URL.
// The API endpoint returns a 302 redirect to the actual file content.
function oneDriveDownloadUrl(shareUrl) {
    const encoded = Buffer.from(shareUrl)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    return 'https://api.onedrive.com/v1.0/shares/u!' + encoded + '/root/content';
}

// Fetch text content from a OneDrive share URL, following redirects.
function fetchOneDriveText(shareUrl, maxSize, cb) {
    const apiUrl = oneDriveDownloadUrl(shareUrl);
    let redirects = 0;
    const MAX_REDIRECTS = 10;

    function doRequest(url) {
        let done = false;
        const finish = (err, body) => {
            if (done) return;
            done = true;
            cb(err, body);
        };

        try {
            const req = https.get(url, {
                headers: { 'User-Agent': 'jvhd-auth/2.0' },
            }, res => {
                // Follow redirects (301, 302, 303, 307, 308)
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    redirects++;
                    if (redirects > MAX_REDIRECTS) {
                        return finish(new Error('OneDrive qua nhieu redirect'));
                    }
                    doRequest(res.headers.location);
                    return;
                }

                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return finish(new Error('OneDrive HTTP ' + res.statusCode));
                }

                let body = '';
                let size = 0;
                res.on('data', chunk => {
                    size += chunk.length;
                    if (size > (maxSize || REMOTE_MAX_BODY)) {
                        req.destroy(new Error('OneDrive response qua lon'));
                        return;
                    }
                    body += chunk;
                });
                res.on('end', () => finish(null, body));
            });

            req.on('error', e => finish(e, ''));
            req.setTimeout(15000, () => req.destroy(new Error('OneDrive timeout')));
        } catch (e) {
            finish(e, '');
        }
    }

    doRequest(apiUrl);
}

// ---- Data cache (OneDrive) --------------------------------------------------
// Cache structure: { data, loadedAt (ms timestamp), ok, error }
let memberCache = { data: null, loadedAt: 0, ok: false, error: null };
let hash4Cache = { list: new Set(), loadedAt: 0, ok: false, error: null };
let targeturlCache = { data: null, loadedAt: 0, ok: false, error: null };

// ---- binding store ----------------------------------------------------------
let bindings = {}; // { [hash64]: { k: '<b64 65B>', at: <ms> } }
let bindingState = {
    ready: false,
    source: null,
    loadedAt: null,
    savedAt: null, // kept for API compat; always null (OneDrive is READ ONLY)
    error: null,
};

function cloneBindings(value) {
    return JSON.parse(JSON.stringify(value));
}

function normalizeBindings(value) {
    // Support both internal object and array format from /admin/list.
    const source = Array.isArray(value)
        ? value
        : (value && Array.isArray(value.bindings) ? value.bindings : null);

    let result;
    if (source) {
        result = {};
        for (const item of source) {
            if (!item || typeof item !== 'object') {
                throw new Error('Binding array co phan tu khong hop le');
            }
            result[item.h] = { k: item.k, at: item.at };
        }
    } else if (value && typeof value === 'object') {
        result = value.bindings && typeof value.bindings === 'object'
            ? value.bindings
            : value;
    } else {
        throw new Error('Binding data phai la object hoac array');
    }

    for (const [h, item] of Object.entries(result)) {
        if (!CRYPTO_HASH_RE.test(h)) {
            throw new Error('Binding co username hash khong hop le');
        }
        if (!item || typeof item !== 'object' || typeof item.k !== 'string') {
            throw new Error('Binding cua ' + h + ' khong hop le');
        }
        if (!pubFromRaw(item.k)) {
            throw new Error('Public key cua binding ' + h + ' khong hop le');
        }
        result[h] = {
            k: item.k,
            at: Number.isFinite(Number(item.at)) ? Number(item.at) : Date.now(),
        };
    }
    return result;
}

// ---- Sleep utility ----------------------------------------------------------
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ---- Load all data from OneDrive at startup ---------------------------------
async function loadAllAtStartup() {
    // 1. Load Binding.txt (CRITICAL — server won't start without it)
    let bindingLoaded = false;
    let lastBindingError;
    for (let attempt = 1; attempt <= BINDING_LOAD_ATTEMPTS; attempt++) {
        try {
            console.log('[binding] tai OneDrive Binding.txt lan ' + attempt + '/' + BINDING_LOAD_ATTEMPTS);
            const text = await new Promise((resolve, reject) => {
                fetchOneDriveText(ONEDRIVE_BINDING_URL, REMOTE_MAX_BODY, (err, body) => {
                    if (err) reject(err); else resolve(body);
                });
            });
            const data = JSON.parse(text);
            bindings = normalizeBindings(data);
            bindingState = {
                ready: true,
                source: 'onedrive',
                loadedAt: new Date().toISOString(),
                savedAt: null,
                error: null,
            };
            bindingLoaded = true;
            console.log('[binding] Binding.txt → OK — da nap ' + Object.keys(bindings).length + ' binding');
            break;
        } catch (e) {
            lastBindingError = e;
            console.error('[binding] Binding.txt → ERROR:', e.message);
            if (attempt < BINDING_LOAD_ATTEMPTS) {
                await sleep(2000 * Math.pow(2, attempt - 1));
            }
        }
    }
    if (!bindingLoaded) {
        bindingState.ready = false;
        bindingState.error = lastBindingError ? lastBindingError.message : 'unknown error';
        throw lastBindingError || new Error('Khong nap duoc Binding.txt tu OneDrive');
    }

    // 2. Load Hash4.txt (important for auth — log error but don't fail startup)
    try {
        const text = await new Promise((resolve, reject) => {
            fetchOneDriveText(ONEDRIVE_HASH4_URL, REMOTE_MAX_BODY, (err, body) => {
                if (err) reject(err); else resolve(body);
            });
        });
        const data = JSON.parse(text);
        if (!Array.isArray(data)) throw new Error('Hash4.txt khong phai JSON array');
        const set = new Set(data.filter(
            x => typeof x === 'string' && CRYPTO_HASH_RE.test(x)
        ));
        hash4Cache = { list: set, loadedAt: Date.now(), ok: true, error: null };
        console.log('[hash4] Hash4.txt → OK — da nap ' + set.size + ' hash');
    } catch (e) {
        hash4Cache = { list: new Set(), loadedAt: 0, ok: false, error: e.message };
        console.error('[hash4] Hash4.txt → ERROR:', e.message);
    }

    // 3. Load Member.txt (non-critical)
    try {
        const text = await new Promise((resolve, reject) => {
            fetchOneDriveText(ONEDRIVE_MEMBER_URL, REMOTE_MAX_BODY, (err, body) => {
                if (err) reject(err); else resolve(body);
            });
        });
        const data = JSON.parse(text);
        if (!Array.isArray(data)) throw new Error('Member.txt khong phai JSON array');
        memberCache = { data, loadedAt: Date.now(), ok: true, error: null };
        console.log('[member] Member.txt → OK — da nap ' + data.length + ' member');
    } catch (e) {
        memberCache = { data: null, loadedAt: 0, ok: false, error: e.message };
        console.error('[member] Member.txt → ERROR:', e.message);
    }

    // 4. Load TargetUrl.txt (non-critical)
    try {
        const text = await new Promise((resolve, reject) => {
            fetchOneDriveText(ONEDRIVE_TARGETURL_URL, REMOTE_MAX_BODY, (err, body) => {
                if (err) reject(err); else resolve(body);
            });
        });
        const data = JSON.parse(text);
        targeturlCache = { data, loadedAt: Date.now(), ok: true, error: null };
        console.log('[targeturl] TargetUrl.txt → OK');
    } catch (e) {
        targeturlCache = { data: null, loadedAt: 0, ok: false, error: e.message };
        console.error('[targeturl] TargetUrl.txt → ERROR:', e.message);
    }
}

// ---- Allowlist (from Hash4.txt OneDrive cache) ------------------------------
// Callback receives { list: Set, ok: boolean } — same interface as before.
function fetchAllowlist(cb) {
    const now = Date.now();

    // Static override (for testing / fallback)
    if (ALLOWLIST_STATIC) {
        try {
            const set = new Set(JSON.parse(ALLOWLIST_STATIC).filter(
                x => typeof x === 'string' && CRYPTO_HASH_RE.test(x)
            ));
            return cb({ list: set, ok: true });
        } catch (e) {
            return cb({ list: new Set(), ok: false });
        }
    }

    // Use fresh cache if available
    if (hash4Cache.ok && (now - hash4Cache.loadedAt < ONEDRIVE_TTL_MS)) {
        return cb({ list: hash4Cache.list, ok: true });
    }

    // Refresh from OneDrive Hash4.txt
    fetchOneDriveText(ONEDRIVE_HASH4_URL, REMOTE_MAX_BODY, (err, text) => {
        if (!err) {
            try {
                const data = JSON.parse(text);
                if (Array.isArray(data)) {
                    const set = new Set(data.filter(
                        x => typeof x === 'string' && CRYPTO_HASH_RE.test(x)
                    ));
                    hash4Cache = { list: set, loadedAt: now, ok: true, error: null };
                    return cb({ list: set, ok: true });
                }
            } catch (e) { /* fall through to stale cache */ }
        }
        // If refresh failed but we have stale cache, use it briefly
        if (hash4Cache.ok) {
            console.error('[hash4] refresh that bai, dung cache cu');
            return cb({ list: hash4Cache.list, ok: true });
        }
        if (err) console.error('[hash4] fetch loi:', err.message);
        cb({ list: new Set(), ok: false });
    });
}

// ---- mutateBindings (in-memory ONLY — OneDrive is READ ONLY) ---------------
// Queue mutations so two requests don't overwrite each other in the same process.
let mutationQueue = Promise.resolve();
function mutateBindings(mutator) {
    const operation = mutationQueue.then(async () => {
        if (!bindingState.ready) throw new Error('Binding store chua san sang');
        const before = cloneBindings(bindings);
        try {
            const result = mutator();
            // NOTE: OneDrive is READ ONLY — bindings are kept in-memory only.
            // New bindings will be lost when the server restarts.
            // To persist, admin must manually update Binding.txt on OneDrive.
            bindingState.error = null;
            return result;
        } catch (e) {
            bindings = before;
            bindingState.error = e.message;
            throw e;
        }
    });
    mutationQueue = operation.catch(() => {});
    return operation;
}

// ---- challenge / nonce ------------------------------------------------------
const pending = {};
function newNonce(h, kind) {
    const value = crypto.randomBytes(32).toString('base64');
    pending[h] = { v: value, kind, exp: Date.now() + CHALLENGE_TTL_MS };
    return value;
}

function takeNonce(h, kind, value) {
    const item = pending[h];
    delete pending[h];
    if (!item || item.kind !== kind || item.v !== value || Date.now() > item.exp) return null;
    return item.v;
}

setInterval(() => {
    const now = Date.now();
    for (const key of Object.keys(pending)) {
        if (pending[key].exp < now - 60000) delete pending[key];
    }
}, 60000).unref();

// ---- HTTP helpers -----------------------------------------------------------
function send(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
}

function readBody(req, cb) {
    let body = '';
    let size = 0;
    let rejected = false;
    req.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_BODY) {
            rejected = true;
            return;
        }
        body += chunk;
    });
    req.on('end', () => {
        if (rejected) return cb(new Error('body qua lon'));
        try {
            cb(null, JSON.parse(body || '{}'));
        } catch (e) {
            cb(new Error('bad json'));
        }
    });
    req.on('error', () => cb(new Error('read error')));
}

// ---- handlers ---------------------------------------------------------------
function handleStart(req, res, body) {
    const h = body.h;
    if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h)) {
        return send(res, 400, { status: 'bad' });
    }
    if (!bindingState.ready) {
        return send(res, 503, { status: 'unavailable' });
    }
    fetchAllowlist(al => {
        if (!al.ok || !al.list.has(h)) return send(res, 200, { status: 'unknown' });
        if (bindings[h]) {
            return send(res, 200, {
                status: 'challenge',
                challenge: newNonce(h, 'verify'),
            });
        }
        return send(res, 200, { status: 'bind', nonce: newNonce(h, 'bind') });
    });
}

async function handleBind(req, res, body) {
    const { h, k } = body;
    if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h) || typeof k !== 'string') {
        return send(res, 400, { status: 'bad' });
    }
    if (!bindingState.ready) return send(res, 503, { status: 'unavailable' });

    const nonce = takeNonce(h, 'bind', body.nonce);
    if (!nonce) return send(res, 200, { status: 'bad' });
    const keyObj = pubFromRaw(k);
    if (!keyObj) return send(res, 200, { status: 'bad' });
    if (!verifySig(keyObj, Buffer.from(nonce, 'base64'), body.sig)) {
        return send(res, 200, { status: 'bad' });
    }

    try {
        const result = await mutateBindings(() => {
            if (bindings[h]) return 'denied';
            bindings[h] = { k, at: Date.now() };
            return 'ok';
        });
        return send(res, 200, { status: result });
    } catch (e) {
        console.error('[binding] khong luu duoc binding moi:', e.message);
        return send(res, 503, { status: 'unavailable' });
    }
}

function handleVerify(req, res, body) {
    const h = body.h;
    if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h)) {
        return send(res, 400, { status: 'bad' });
    }
    if (!bindingState.ready) return send(res, 503, { status: 'unavailable' });
    const item = pending[h];
    const challenge = takeNonce(h, 'verify', item ? item.v : undefined);
    const bound = bindings[h];
    if (!challenge || !bound) return send(res, 200, { status: 'denied' });
    const keyObj = pubFromRaw(bound.k);
    if (!keyObj || !verifySig(keyObj, Buffer.from(challenge, 'base64'), body.sig)) {
        return send(res, 200, { status: 'denied' });
    }
    return send(res, 200, { status: 'ok' });
}

async function handleAdmin(req, res, body, url) {
    if (!ADMIN_TOKEN) return send(res, 500, { error: 'server chua cau hinh ADMIN_TOKEN' });
    if (String(body.token || url.searchParams.get('token') || '') !== ADMIN_TOKEN) {
        return send(res, 403, { error: 'sai token' });
    }
    if (!bindingState.ready) {
        return send(res, 503, { ok: false, error: 'binding store chua san sang' });
    }

    if (url.pathname === '/admin/unbind') {
        const h = body.h;
        if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h)) {
            return send(res, 400, { error: 'hash khong hop le' });
        }
        try {
            const removed = await mutateBindings(() => {
                if (!bindings[h]) return false;
                delete bindings[h];
                delete pending[h];
                return true;
            });
            if (!removed) return send(res, 200, { ok: false, error: 'khong co binding' });
            return send(res, 200, { ok: true });
        } catch (e) {
            console.error('[binding] unbind loi:', e.message);
            return send(res, 503, { ok: false, error: 'loi binding store' });
        }
    }

    if (url.pathname === '/admin/list') {
        return send(res, 200, {
            ok: true,
            ready: bindingState.ready,
            source: bindingState.source,
            loadedAt: bindingState.loadedAt,
            savedAt: bindingState.savedAt,
            count: Object.keys(bindings).length,
            bindings: Object.entries(bindings).map(([h, value]) => ({
                h,
                k: value.k,
                at: value.at,
            })),
            // OneDrive data source status (for admin visibility)
            onedrive: {
                member: {
                    ok: memberCache.ok,
                    loadedAt: memberCache.loadedAt ? new Date(memberCache.loadedAt).toISOString() : null,
                    count: memberCache.data ? memberCache.data.length : 0,
                    error: memberCache.error,
                },
                hash4: {
                    ok: hash4Cache.ok,
                    loadedAt: hash4Cache.loadedAt ? new Date(hash4Cache.loadedAt).toISOString() : null,
                    count: hash4Cache.list.size,
                    error: hash4Cache.error,
                },
                binding: {
                    ok: bindingState.ready,
                    loadedAt: bindingState.loadedAt,
                    error: bindingState.error,
                },
                targeturl: {
                    ok: targeturlCache.ok,
                    loadedAt: targeturlCache.loadedAt ? new Date(targeturlCache.loadedAt).toISOString() : null,
                    error: targeturlCache.error,
                },
            },
        });
    }
    return send(res, 404, { error: 'khong ro' });
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '600',
        });
        return res.end();
    }
    if (req.method === 'GET' && url.pathname === '/health') {
        return send(res, bindingState.ready ? 200 : 503, {
            ok: bindingState.ready,
            bindingReady: bindingState.ready,
            bindings: Object.keys(bindings).length,
            bindingSource: bindingState.source,
            bindingLoadedAt: bindingState.loadedAt,
            bindingSavedAt: bindingState.savedAt,
            bindingError: bindingState.error,
        });
    }
    if (req.method === 'GET' && url.pathname === '/admin/list') {
        handleAdmin(req, res, {}, url).catch(e => {
            console.error(e);
            if (!res.headersSent) send(res, 500, { error: 'internal' });
        });
        return;
    }
    if (req.method !== 'POST') return send(res, 405, { error: 'method' });

    readBody(req, (err, body) => {
        if (err) return send(res, 400, { error: 'bad request' });
        let result;
        switch (url.pathname) {
            case '/auth/start':
                result = handleStart(req, res, body);
                break;
            case '/auth/bind':
                result = handleBind(req, res, body);
                break;
            case '/auth/verify':
                result = handleVerify(req, res, body);
                break;
            case '/admin/unbind':
                result = handleAdmin(req, res, body, url);
                break;
            default:
                return send(res, 404, { error: 'not found' });
        }
        if (result && typeof result.catch === 'function') {
            result.catch(e => {
                console.error('[http] handler error:', e);
                if (!res.headersSent) send(res, 500, { error: 'internal' });
            });
        }
    });
});

async function startServer() {
    if (!ADMIN_TOKEN) {
        console.error('[startup] CANH BAO: ADMIN_TOKEN chua duoc cau hinh');
    }
    try {
        await loadAllAtStartup();
    } catch (e) {
        console.error('[startup] KHONG NAP DUOC DATA TU ONEDRIVE:', e.message);
        console.error('[startup] dung server de dam bao fail-closed');
        process.exitCode = 1;
        return;
    }
    server.listen(PORT, HOST, () => {
        console.log('[auth] lang nghe tai http://' + HOST + ':' + PORT);
    });
}

if (require.main === module) startServer();

module.exports = {
    server,
    startServer,
    _internals: {
        pubFromRaw,
        verifySig,
        takeNonce,
        newNonce,
        bindingsRef: () => bindings,
        bindingStateRef: () => bindingState,
        memberCacheRef: () => memberCache,
        hash4CacheRef: () => hash4Cache,
        targeturlCacheRef: () => targeturlCache,
        normalizeBindings,
    },
};