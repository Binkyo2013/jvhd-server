'use strict';
// ============================================================================
// JVHD AUTH SERVER — Device Binding + Challenge/Response (Yc11)
// ============================================================================
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');

const ALLOWLIST_JSON_URL = process.env.ALLOWLIST_JSON_URL ||
    'https://api.jsonbin.io/v3/b/6a9245b5f5f4af5e29504b20/latest';
const ALLOWLIST_STATIC = process.env.ALLOWLIST_STATIC || '';
const ALLOWLIST_TTL_MS = parseInt(process.env.ALLOWLIST_TTL_MS || '60000', 10);

// JSONBin rieng dung de luu binding. KHONG ghi key truc tiep vao source code.
const BINDING_BIN_URL = process.env.BINDING_BIN_URL || '';
const BINDING_BIN_KEY = process.env.BINDING_BIN_KEY || '';
const BINDING_BIN_KEY_HEADER = process.env.BINDING_BIN_KEY_HEADER || 'X-Master-Key';
const BINDING_LOAD_ATTEMPTS = parseInt(process.env.BINDING_LOAD_ATTEMPTS || '5', 10);

const CHALLENGE_TTL_MS = parseInt(process.env.CHALLENGE_TTL_MS || '120000', 10);
const MAX_BODY = parseInt(process.env.MAX_BODY || '16384', 10);
const REMOTE_MAX_BODY = parseInt(process.env.REMOTE_MAX_BODY || String(MAX_BODY * 100), 10);

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

// ---- binding store ----------------------------------------------------------
let bindings = {}; // { [hash64]: { k: '<b64 65B>', at: <ms> } }
let bindingState = {
    ready: false,
    source: null,
    loadedAt: null,
    savedAt: null,
    error: null,
};

function cloneBindings(value) {
    return JSON.parse(JSON.stringify(value));
}

function normalizeBindings(value) {
    // Ho tro ca object noi bo va mang do /admin/list tra ve.
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

function loadLocalData() {
    try {
        const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
        bindings = normalizeBindings(data);
        bindingState = {
            ready: true,
            source: 'local',
            loadedAt: new Date().toISOString(),
            savedAt: null,
            error: null,
        };
        return true;
    } catch (e) {
        return false;
    }
}

function saveLocalData() {
    const tmp = DATA_FILE + '.tmp';
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(tmp, JSON.stringify({ bindings }, null, 2));
    fs.renameSync(tmp, DATA_FILE);
}

function jsonBinRequest(method, body) {
    return new Promise((resolve, reject) => {
        if (!BINDING_BIN_URL) return reject(new Error('Thieu BINDING_BIN_URL'));
        if (!BINDING_BIN_KEY) return reject(new Error('Thieu BINDING_BIN_KEY'));
        if (!/^X-(Master|Access)-Key$/i.test(BINDING_BIN_KEY_HEADER)) {
            return reject(new Error('BINDING_BIN_KEY_HEADER khong hop le'));
        }

        let target;
        try {
            target = new URL(BINDING_BIN_URL);
        } catch (e) {
            return reject(new Error('BINDING_BIN_URL khong hop le'));
        }
        if (target.protocol !== 'https:') {
            return reject(new Error('BINDING_BIN_URL phai dung HTTPS'));
        }

        // JSONBin PUT dung /v3/b/<id>, khong dung hau to /latest.
        if (method === 'PUT') target.pathname = target.pathname.replace(/\/latest\/?$/, '');
        if (method === 'GET') target.searchParams.set('ts', String(Date.now()));

        const payload = body === undefined ? null : JSON.stringify(body);
        const headers = {
            'User-Agent': 'jvhd-auth/2.0',
            [BINDING_BIN_KEY_HEADER]: BINDING_BIN_KEY,
            'Cache-Control': 'no-cache',
        };
        if (payload !== null) {
            headers['Content-Type'] = 'application/json';
            headers['Content-Length'] = Buffer.byteLength(payload);
        }

        let settled = false;
        const finish = (err, value) => {
            if (settled) return;
            settled = true;
            if (err) reject(err); else resolve(value);
        };

        const req = https.request(target, { method, headers }, res => {
            let text = '';
            let size = 0;
            res.on('data', chunk => {
                size += chunk.length;
                if (size > REMOTE_MAX_BODY) {
                    req.destroy(new Error('JSONBin response qua lon'));
                    return;
                }
                text += chunk;
            });
            res.on('end', () => {
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return finish(new Error(
                        'JSONBin HTTP ' + res.statusCode + ': ' + text.slice(0, 300)
                    ));
                }
                try {
                    finish(null, text ? JSON.parse(text) : {});
                } catch (e) {
                    finish(new Error('JSONBin tra ve JSON khong hop le'));
                }
            });
        });
        req.on('error', finish);
        req.setTimeout(15000, () => req.destroy(new Error('JSONBin timeout')));
        if (payload !== null) req.write(payload);
        req.end();
    });
}

async function loadBindingsFromJsonBin() {
    const payload = await jsonBinRequest('GET');
    if (!Object.prototype.hasOwnProperty.call(payload, 'record')) {
        throw new Error('JSONBin response khong co truong record');
    }
    return normalizeBindings(payload.record);
}

async function saveBindingsToJsonBin() {
    // JSONBin se boc body nay trong truong "record" khi doc lai.
    await jsonBinRequest('PUT', { bindings });
    bindingState.savedAt = new Date().toISOString();
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function loadBindingsAtStartup() {
    let lastError;
    for (let attempt = 1; attempt <= BINDING_LOAD_ATTEMPTS; attempt++) {
        try {
            console.log('[binding] tai JSONBin lan ' + attempt + '/' + BINDING_LOAD_ATTEMPTS);
            const loaded = await loadBindingsFromJsonBin();
            bindings = loaded;
            bindingState = {
                ready: true,
                source: 'jsonbin',
                loadedAt: new Date().toISOString(),
                savedAt: null,
                error: null,
            };
            try {
                saveLocalData();
            } catch (e) {
                console.error('[binding] khong ghi duoc local backup:', e.message);
            }
            console.log('[binding] da nap ' + Object.keys(bindings).length + ' binding');
            return;
        } catch (e) {
            lastError = e;
            console.error('[binding] tai that bai:', e.message);
            if (attempt < BINDING_LOAD_ATTEMPTS) {
                await sleep(2000 * Math.pow(2, attempt - 1));
            }
        }
    }
    bindingState.ready = false;
    bindingState.error = lastError ? lastError.message : 'unknown error';
    throw lastError || new Error('Khong nap duoc binding data');
}

// Xep hang cac thay doi de hai request khong ghi de len nhau trong cung process.
let mutationQueue = Promise.resolve();
function mutateBindings(mutator) {
    const operation = mutationQueue.then(async () => {
        if (!bindingState.ready) throw new Error('Binding store chua san sang');
        const before = cloneBindings(bindings);
        try {
            const result = mutator();
            await saveBindingsToJsonBin();
            try {
                saveLocalData();
            } catch (e) {
                console.error('[binding] local backup that bai:', e.message);
            }
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

// ---- allowlist --------------------------------------------------------------
let allowCache = { list: new Set(), at: 0, ok: false };
function fetchAllowlist(cb) {
    const now = Date.now();
    if (ALLOWLIST_STATIC) {
        try {
            allowCache = { list: new Set(JSON.parse(ALLOWLIST_STATIC)), at: now, ok: true };
        } catch (e) {
            allowCache = { list: new Set(), at: now, ok: false };
        }
        return cb(allowCache);
    }
    if (allowCache.ok && now - allowCache.at < ALLOWLIST_TTL_MS) return cb(allowCache);
    const u = ALLOWLIST_JSON_URL + (ALLOWLIST_JSON_URL.includes('?') ? '&' : '?') + 'ts=' + now;
    httpsGet(u, (err, body) => {
        if (!err) {
            try {
                const rec = JSON.parse(body).record;
                if (Array.isArray(rec)) {
                    const set = new Set(rec.filter(
                        x => typeof x === 'string' && CRYPTO_HASH_RE.test(x)
                    ));
                    allowCache = { list: set, at: now, ok: true };
                }
            } catch (e) { /* giu cache cu */ }
        }
        cb(allowCache);
    });
}

function httpsGet(url, cb) {
    let done = false;
    const finish = (e, body) => {
        if (!done) {
            done = true;
            cb(e, body);
        }
    };
    try {
        const req = https.get(url, { headers: { 'User-Agent': 'jvhd-auth/2.0' } }, res => {
            let body = '';
            let size = 0;
            res.on('data', chunk => {
                size += chunk.length;
                if (size <= MAX_BODY * 40) body += chunk;
            });
            res.on('end', () => finish(
                res.statusCode >= 200 && res.statusCode < 300
                    ? null
                    : new Error('HTTP ' + res.statusCode),
                body
            ));
        });
        req.on('error', e => finish(e, ''));
        req.setTimeout(8000, () => req.destroy(new Error('timeout')));
    } catch (e) {
        finish(e, '');
    }
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
            console.error('[binding] unbind khong luu duoc:', e.message);
            return send(res, 503, { ok: false, error: 'khong luu duoc JSONBin' });
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
        await loadBindingsAtStartup();
    } catch (e) {
        console.error('[startup] KHONG NAP DUOC BINDING DATA:', e.message);
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
        loadLocalData,
        saveLocalData,
        loadBindingsFromJsonBin,
        saveBindingsToJsonBin,
        normalizeBindings,
    },
};
