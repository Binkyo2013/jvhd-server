'use strict';
// ============================================================================
// JVHD AUTH SERVER — Device Binding + Challenge/Response (Yc11)
// Binding persistence: GitHub Private Repository (Contents API)
// Member/Hash4/TargetUrl: OneDrive READ ONLY
// ============================================================================
const http = require('http');
const https = require('https');
const crypto = require('crypto');

// ---- Configuration ----------------------------------------------------------
const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

// ---- OneDrive share URLs (Member, Hash4, TargetUrl — READ ONLY) -------------
const ONEDRIVE_MEMBER_URL = process.env.ONEDRIVE_MEMBER_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQBDC0QATqfRR4ROzrev8HbZAYl9Ie1vzNapxj7CTMPX08g?e=coaE1V';
const ONEDRIVE_HASH4_URL = process.env.ONEDRIVE_HASH4_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQDDyKOWH_aLS40GJvPdPhK9AWjPGlotl_cqrjuD8fBGHtY?e=Sbe5u2';
const ONEDRIVE_TARGETURL_URL = process.env.ONEDRIVE_TARGETURL_URL ||
    'https://1drv.ms/t/c/3d6a4ca52f4e4e18/IQBzWVFIXQRfRY5w1af6pNjxAYwIHtGQEk_OX2EV-_i_XRw?e=K8wJkD';

// ---- GitHub Binding storage -------------------------------------------------
// Binding.txt is stored in a PRIVATE GitHub repository and read/written via
// GitHub Contents API. All five variables MUST be set on Render.
var GITHUB_TOKEN        = process.env.GITHUB_TOKEN || '';
var GITHUB_OWNER        = process.env.GITHUB_OWNER || '';
var GITHUB_REPO         = process.env.GITHUB_REPO || '';
var GITHUB_BINDING_PATH = process.env.GITHUB_BINDING_PATH || '';
var GITHUB_BRANCH       = process.env.GITHUB_BRANCH || '';

var GITHUB_MAX_CONFLICT_RETRIES = 3;

// ---- Other config -----------------------------------------------------------
var ONEDRIVE_TTL_MS = parseInt(process.env.ONEDRIVE_TTL_MS || '60000', 10);
var ALLOWLIST_STATIC = process.env.ALLOWLIST_STATIC || '';

var CHALLENGE_TTL_MS = parseInt(process.env.CHALLENGE_TTL_MS || '120000', 10);
var MAX_BODY = parseInt(process.env.MAX_BODY || '16384', 10);
var REMOTE_MAX_BODY = parseInt(process.env.REMOTE_MAX_BODY || String(MAX_BODY * 100), 10);
var BINDING_LOAD_ATTEMPTS = parseInt(process.env.BINDING_LOAD_ATTEMPTS || '5', 10);

var CRYPTO_HASH_RE = /^[0-9a-f]{64}$/;
var SPKI_P256 = Buffer.from(
    '3059301306072a8648ce3d020106082a8648ce3d030107034200',
    'hex'
);

// ---- ECDSA P-256 ------------------------------------------------------------
function pubFromRaw(kB64) {
    try {
        var raw = Buffer.from(String(kB64), 'base64');
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

// ---- OneDrive reader --------------------------------------------------------
// Used for Member, Hash4, TargetUrl (read-only shared files).
// Strategy:
//   1. Follow 1drv.ms redirect → extract resid/redeem from redirect URL
//   2. Construct download URL (onedrive.live.com/download?resid=...&authkey=...)
//   3. Fetch actual file content (not HTML web viewer)
//   4. Fallback to api.onedrive.com endpoint
// Both methods reject HTML responses and only accept file content.

var _odCookies = {}; // domain → { name → value }

function _odCookieStr(host) {
    var jar = _odCookies[host];
    if (!jar) return '';
    var parts = [];
    var keys = Object.keys(jar);
    for (var i = 0; i < keys.length; i++) parts.push(keys[i] + '=' + jar[keys[i]]);
    return parts.join('; ');
}

function _odSaveCookies(host, hdr) {
    if (!hdr) return;
    if (!_odCookies[host]) _odCookies[host] = {};
    var arr = Array.isArray(hdr) ? hdr : [hdr];
    for (var i = 0; i < arr.length; i++) {
        var seg = String(arr[i]).split(';')[0];
        var eq = seg.indexOf('=');
        if (eq > 0) _odCookies[host][seg.slice(0, eq).trim()] = seg.slice(eq + 1).trim();
    }
}

// Sanitize URL for logging: keep hostname + path, mask query param values
function _odSanitizeUrl(rawUrl) {
    try {
        var u = new URL(rawUrl);
        var safe = u.hostname + u.pathname;
        var params = [];
        u.searchParams.forEach(function (val, key) { params.push(key + '=***'); });
        if (params.length) safe += '?' + params.join('&');
        return safe;
    } catch (e) { return '***'; }
}

// Detect if response is HTML (OneDrive web viewer, not file content)
function _odIsHtml(body, contentType) {
    if (contentType && contentType.toLowerCase().indexOf('text/html') !== -1) return true;
    if (!body || body.length < 10) return false;
    var head = body.slice(0, 200).toUpperCase();
    return head.indexOf('<!DOCTYPE') !== -1 || head.indexOf('<HTML') !== -1;
}

// Build download URL from OneDrive redirect URL by extracting resid + redeem
function _odBuildDownloadUrl(redirectUrl) {
    try {
        var u = new URL(redirectUrl);
        var resid = u.searchParams.get('resid');
        var redeem = u.searchParams.get('redeem');
        if (!resid) return null;
        var dl = 'https://onedrive.live.com/download?resid=' + encodeURIComponent(resid);
        if (redeem) dl += '&authkey=' + encodeURIComponent(redeem);
        return dl;
    } catch (e) { return null; }
}

function fetchOneDriveText(shareUrl, maxSize, cb) {
    // Primary: follow redirects → extract download URL → fetch file
    _odFetchDirect(shareUrl, maxSize, function (err, body) {
        if (!err) return cb(null, body);
        // Fallback: api.onedrive.com endpoint
        _odFetchApi(shareUrl, maxSize, function (err2, body2) {
            if (!err2) return cb(null, body2);
            cb(err); // return primary error
        });
    });
}

// Primary: follow 1drv.ms redirects, extract resid/redeem, download file
function _odFetchDirect(shareUrl, maxSize, cb) {
    var redirects = 0;
    var MAX_REDIRECTS = 10;
    var firstRedirectUrl = null; // save first redirect (has resid/redeem)

    function go(url, base) {
        var done = false;
        var finish = function (e, b) { if (!done) { done = true; cb(e, b); } };

        try {
            var u = new URL(url);
            var host = u.hostname;

            var headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'identity',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Upgrade-Insecure-Requests': '1',
            };
            var ck = _odCookieStr(host);
            if (ck) headers['Cookie'] = ck;

            console.log('[onedrive] GET ' + host + '...');

            var req = https.get(url, { headers: headers }, function (res) {
                _odSaveCookies(host, res.headers['set-cookie']);
                var ct = res.headers['content-type'] || '?';
                var cl = res.headers['content-length'] || '?';
                console.log('[onedrive] ← HTTP ' + res.statusCode + ' ct=' + ct + ' cl=' + cl);

                // Follow 3xx redirects
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    if (++redirects > MAX_REDIRECTS) return finish(new Error('OneDrive qua nhieu redirect'));
                    var next;
                    try { next = new URL(res.headers.location, base || url).toString(); } catch (e) { next = res.headers.location; }
                    // Save first redirect (contains resid/redeem for download URL)
                    if (!firstRedirectUrl) firstRedirectUrl = next;
                    console.log('[onedrive] redirect ' + res.statusCode + ' → ' + _odSanitizeUrl(next));
                    res.resume();
                    go(next, next);
                    return;
                }

                // Error response
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    var eb = ''; var es = 0;
                    res.on('data', function (c) { es += c.length; if (es < 500) eb += c.toString(); });
                    res.on('end', function () {
                        console.log('[onedrive] error body: ' + eb.replace(/[\w+\/=-]{20,}/g, '***').slice(0, 300));
                        finish(new Error('[onedrive] GET ' + host + ' → HTTP ' + res.statusCode));
                    });
                    return;
                }

                // HTTP 200 — read body
                var body = ''; var size = 0;
                res.on('data', function (c) {
                    size += c.length;
                    if (size > (maxSize || REMOTE_MAX_BODY)) { req.destroy(new Error('OneDrive response qua lon')); return; }
                    body += c;
                });
                res.on('end', function () {
                    // If HTML web viewer → try download URL from redirect params
                    if (_odIsHtml(body, ct)) {
                        console.log('[onedrive] ← HTML web viewer, extracting download URL...');
                        var dlUrl = _odBuildDownloadUrl(firstRedirectUrl);
                        if (dlUrl) {
                            console.log('[onedrive] → trying download endpoint...');
                            _odFetchFile(dlUrl, maxSize, finish);
                            return;
                        }
                        return finish(new Error('[onedrive] no resid in redirect, cannot download'));
                    }
                    // Not HTML — this is actual file content
                    console.log('[onedrive] ← OK (' + size + ' bytes, ct=' + ct + ')');
                    finish(null, body);
                });
            });

            req.on('error', function (e) { finish(e, ''); });
            req.setTimeout(15000, function () { req.destroy(new Error('OneDrive timeout')); });
        } catch (e) { finish(e, ''); }
    }

    go(shareUrl, shareUrl);
}

// Fetch file from download URL (follows redirects, rejects HTML)
function _odFetchFile(url, maxSize, cb) {
    var redirects = 0;
    var MAX_REDIRECTS = 10;

    function go(targetUrl) {
        var done = false;
        var finish = function (e, b) { if (!done) { done = true; cb(e, b); } };

        try {
            var req = https.get(targetUrl, {
                headers: { 'User-Agent': 'jvhd-auth/2.0', 'Accept': '*/*' },
            }, function (res) {
                var ct = res.headers['content-type'] || '?';
                console.log('[onedrive-dl] ← HTTP ' + res.statusCode + ' ct=' + ct);

                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    if (++redirects > MAX_REDIRECTS) return finish(new Error('qua nhieu redirect'));
                    var next;
                    try { next = new URL(res.headers.location, targetUrl).toString(); } catch (e) { next = res.headers.location; }
                    console.log('[onedrive-dl] redirect → ' + _odSanitizeUrl(next));
                    res.resume();
                    go(next);
                    return;
                }

                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return finish(new Error('[onedrive-dl] → HTTP ' + res.statusCode));
                }

                var body = ''; var size = 0;
                res.on('data', function (c) {
                    size += c.length;
                    if (size > maxSize) { req.destroy(new Error('qua lon')); return; }
                    body += c;
                });
                res.on('end', function () {
                    if (_odIsHtml(body, ct)) {
                        console.log('[onedrive-dl] ← HTML detected, rejecting');
                        return finish(new Error('[onedrive-dl] received HTML instead of file'));
                    }
                    console.log('[onedrive-dl] ← OK (' + size + ' bytes, ct=' + ct + ')');
                    finish(null, body);
                });
            });

            req.on('error', function (e) { finish(e, ''); });
            req.setTimeout(15000, function () { req.destroy(new Error('timeout')); });
        } catch (e) { finish(e, ''); }
    }

    go(url);
}

// Fallback: api.onedrive.com endpoint (no browser headers, no cookies)
// Returns 302 → CDN URL with actual file content (or 401 if not authorized).
function _odFetchApi(shareUrl, maxSize, cb) {
    var encoded = Buffer.from(shareUrl).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    var apiUrl = 'https://api.onedrive.com/v1.0/shares/u!' + encoded + '/root/content';

    console.log('[onedrive-api] trying api.onedrive.com...');

    var done = false;
    var finish = function (e, b) { if (!done) { done = true; cb(e, b); } };

    function doFetch(targetUrl, isRedirect) {
        try {
            var req = https.get(targetUrl, {
                headers: { 'User-Agent': 'jvhd-auth/2.0', 'Accept': '*/*' },
            }, function (res) {
                var ct = res.headers['content-type'] || '?';
                console.log('[onedrive-api] ← HTTP ' + res.statusCode + ' ct=' + ct + (isRedirect ? ' (redirect)' : ''));

                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    var next = res.headers.location;
                    console.log('[onedrive-api] redirect → ' + _odSanitizeUrl(next));
                    res.resume();
                    doFetch(next, true);
                    return;
                }

                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return finish(new Error('[onedrive-api] → HTTP ' + res.statusCode));
                }

                var body = ''; var size = 0;
                res.on('data', function (c) {
                    size += c.length;
                    if (size > (maxSize || REMOTE_MAX_BODY)) { req.destroy(new Error('qua lon')); return; }
                    body += c;
                });
                res.on('end', function () {
                    if (_odIsHtml(body, ct)) {
                        console.log('[onedrive-api] ← HTML detected, rejecting');
                        return finish(new Error('[onedrive-api] received HTML instead of file'));
                    }
                    console.log('[onedrive-api] ← OK (' + size + ' bytes, ct=' + ct + ')');
                    finish(null, body);
                });
            });

            req.on('error', function (e) { finish(e, ''); });
            req.setTimeout(15000, function () { req.destroy(new Error('timeout')); });
        } catch (e) { finish(e, ''); }
    }

    doFetch(apiUrl, false);
}

// ---- HTTPS fetch utility (Promise-based) ------------------------------------
// Used for GitHub Contents API calls.

function httpsFetch(url, options) {
    options = options || {};
    var method = options.method || 'GET';
    var headers = options.headers ? Object.assign({}, options.headers) : {};
    var body = options.body || null;
    var timeout = options.timeout || 15000;

    return new Promise(function (resolve, reject) {
        var done = false;
        var finish = function (err, result) {
            if (done) return;
            done = true;
            if (err) reject(err); else resolve(result);
        };

        try {
            var u = new URL(url);
            var reqOptions = {
                hostname: u.hostname,
                port: u.port || (u.protocol === 'https:' ? 443 : 80),
                path: u.pathname + u.search,
                method: method,
                headers: Object.assign({ 'User-Agent': 'jvhd-auth/2.0' }, headers),
            };

            var req = https.request(reqOptions, function (res) {
                var responseBody = '';
                var size = 0;
                res.on('data', function (chunk) {
                    size += chunk.length;
                    if (size > REMOTE_MAX_BODY) {
                        req.destroy(new Error('Response qua lon'));
                        return;
                    }
                    responseBody += chunk;
                });
                res.on('end', function () {
                    finish(null, {
                        status: res.statusCode,
                        headers: res.headers,
                        body: responseBody,
                    });
                });
            });

            req.on('error', function (e) { finish(e); });
            req.setTimeout(timeout, function () { req.destroy(new Error('timeout')); });

            if (body !== null) {
                req.write(body);
            }
            req.end();
        } catch (e) {
            finish(e);
        }
    });
}

// ---- GitHub Contents API (Binding.txt READ + WRITE) -------------------------

// Build the GitHub Contents API URL for Binding.txt
function githubContentsUrl() {
    return 'https://api.github.com/repos/' +
        encodeURIComponent(GITHUB_OWNER) + '/' +
        encodeURIComponent(GITHUB_REPO) + '/contents/' +
        encodeURIComponent(GITHUB_BINDING_PATH) +
        '?ref=' + encodeURIComponent(GITHUB_BRANCH);
}

// Common GitHub API headers (never log Authorization value)
function githubHeaders(extra) {
    var h = {
        'Authorization': 'Bearer ' + GITHUB_TOKEN,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'jvhd-auth/2.0',
        'X-GitHub-Api-Version': '2022-11-28',
    };
    if (extra) {
        var keys = Object.keys(extra);
        for (var i = 0; i < keys.length; i++) {
            h[keys[i]] = extra[keys[i]];
        }
    }
    return h;
}

// Read Binding.txt from GitHub. Returns { bindings: <object>, sha: <string> }.
// Throws on any error — caller must handle.
async function githubReadBinding() {
    var url = githubContentsUrl();
    var res = await httpsFetch(url, {
        method: 'GET',
        headers: githubHeaders(),
    });

    if (res.status === 404) {
        throw new Error('[GitHub] GET Binding.txt failed: HTTP 404 (file not found)');
    }
    if (res.status < 200 || res.status >= 300) {
        throw new Error('[GitHub] GET Binding.txt failed: HTTP ' + res.status);
    }

    var data;
    try {
        data = JSON.parse(res.body);
    } catch (e) {
        throw new Error('[GitHub] GET Binding.txt: response khong phai JSON');
    }

    if (!data.content || !data.sha) {
        throw new Error('[GitHub] GET Binding.txt: thieu content hoac sha');
    }

    var text;
    try {
        text = Buffer.from(data.content, 'base64').toString('utf-8');
    } catch (e) {
        throw new Error('[GitHub] GET Binding.txt: base64 decode that bai');
    }

    var parsed;
    try {
        parsed = JSON.parse(text);
    } catch (e) {
        throw new Error('[GitHub] GET Binding.txt: JSON parse that bai');
    }

    return { bindings: parsed, sha: data.sha };
}

// Write Binding.txt to GitHub. Requires the current SHA for conflict detection.
// Returns the new SHA from GitHub on success.
async function githubWriteBinding(content, sha, message) {
    var url = 'https://api.github.com/repos/' +
        encodeURIComponent(GITHUB_OWNER) + '/' +
        encodeURIComponent(GITHUB_REPO) + '/contents/' +
        encodeURIComponent(GITHUB_BINDING_PATH);

    var body = JSON.stringify({
        message: message || 'Update Binding.txt',
        content: Buffer.from(content, 'utf-8').toString('base64'),
        sha: sha,
        branch: GITHUB_BRANCH,
    });

    var res = await httpsFetch(url, {
        method: 'PUT',
        headers: githubHeaders({ 'Content-Type': 'application/json' }),
        body: body,
    });

    if (res.status === 409) {
        throw new Error('[GitHub] PUT Binding.txt failed: HTTP 409 (conflict)');
    }
    if (res.status < 200 || res.status >= 300) {
        throw new Error('[GitHub] PUT Binding.txt failed: HTTP ' + res.status);
    }

    var result;
    try {
        result = JSON.parse(res.body);
    } catch (e) {
        throw new Error('[GitHub] PUT Binding.txt: response khong phai JSON');
    }

    if (!result.content || !result.content.sha) {
        throw new Error('[GitHub] PUT Binding.txt: thieu sha trong response');
    }

    return result.content.sha;
}

// ---- Data cache (OneDrive, read-only files) ---------------------------------
var memberCache = { data: null, loadedAt: 0, ok: false, error: null };
var hash4Cache = { list: new Set(), loadedAt: 0, ok: false, error: null };
var targeturlCache = { data: null, loadedAt: 0, ok: false, error: null };

// ---- binding store ----------------------------------------------------------
var bindings = {}; // { [hash64]: { k: '<b64 65B>', at: <ms> } }
var bindingSha = null; // current SHA of Binding.txt on GitHub (needed for PUT)
var bindingState = {
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
    var source = Array.isArray(value)
        ? value
        : (value && Array.isArray(value.bindings) ? value.bindings : null);

    var result;
    if (source) {
        result = {};
        for (var i = 0; i < source.length; i++) {
            var item = source[i];
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

    var entries = Object.entries(result);
    for (var j = 0; j < entries.length; j++) {
        var h = entries[j][0];
        var bi = entries[j][1];
        if (!CRYPTO_HASH_RE.test(h)) {
            throw new Error('Binding co username hash khong hop le');
        }
        if (!bi || typeof bi !== 'object' || typeof bi.k !== 'string') {
            throw new Error('Binding cua ' + h + ' khong hop le');
        }
        if (!pubFromRaw(bi.k)) {
            throw new Error('Public key cua binding ' + h + ' khong hop le');
        }
        result[h] = {
            k: bi.k,
            at: Number.isFinite(Number(bi.at)) ? Number(bi.at) : Date.now(),
        };
    }
    return result;
}

// Format bindings object for JSON file content
function formatBindingsForSave() {
    return JSON.stringify({ bindings: bindings }, null, 2);
}

// ---- Sleep utility ----------------------------------------------------------
function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// ---- Load all data at startup -----------------------------------------------
// Binding.txt: GitHub Contents API (private repo, auth required)
// Member, Hash4, TargetUrl: OneDrive (public share links, no auth)

async function loadAllAtStartup() {
    // 1. Load Binding.txt from GitHub (CRITICAL — server won't start without it)
    var bindingLoaded = false;
    var lastBindingError;
    for (var attempt = 1; attempt <= BINDING_LOAD_ATTEMPTS; attempt++) {
        try {
            console.log('[binding] tai Binding.txt tu GitHub lan ' + attempt + '/' + BINDING_LOAD_ATTEMPTS);
            var result = await githubReadBinding();
            bindings = normalizeBindings(result.bindings);
            bindingSha = result.sha;
            bindingState = {
                ready: true,
                source: 'github',
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
        throw lastBindingError || new Error('Khong nap duoc Binding.txt tu GitHub');
    }

    // 2. Load Hash4.txt from OneDrive (important for auth — log error but don't fail startup)
    try {
        var h4text = await new Promise(function (resolve, reject) {
            fetchOneDriveText(ONEDRIVE_HASH4_URL, REMOTE_MAX_BODY, function (err, body) {
                if (err) reject(err); else resolve(body);
            });
        });
        var h4data = JSON.parse(h4text);
        if (!Array.isArray(h4data)) throw new Error('Hash4.txt khong phai JSON array');
        var h4set = new Set(h4data.filter(function (x) {
            return typeof x === 'string' && CRYPTO_HASH_RE.test(x);
        }));
        hash4Cache = { list: h4set, loadedAt: Date.now(), ok: true, error: null };
        console.log('[hash4] Hash4.txt → OK — da nap ' + h4set.size + ' hash');
    } catch (e) {
        hash4Cache = { list: new Set(), loadedAt: 0, ok: false, error: e.message };
        console.error('[hash4] Hash4.txt → ERROR:', e.message);
    }

    // 3. Load Member.txt from OneDrive (non-critical)
    try {
        var mtext = await new Promise(function (resolve, reject) {
            fetchOneDriveText(ONEDRIVE_MEMBER_URL, REMOTE_MAX_BODY, function (err, body) {
                if (err) reject(err); else resolve(body);
            });
        });
        var mdata = JSON.parse(mtext);
        if (!Array.isArray(mdata)) throw new Error('Member.txt khong phai JSON array');
        memberCache = { data: mdata, loadedAt: Date.now(), ok: true, error: null };
        console.log('[member] Member.txt → OK — da nap ' + mdata.length + ' member');
    } catch (e) {
        memberCache = { data: null, loadedAt: 0, ok: false, error: e.message };
        console.error('[member] Member.txt → ERROR:', e.message);
    }

    // 4. Load TargetUrl.txt from OneDrive (non-critical)
    try {
        var ttext = await new Promise(function (resolve, reject) {
            fetchOneDriveText(ONEDRIVE_TARGETURL_URL, REMOTE_MAX_BODY, function (err, body) {
                if (err) reject(err); else resolve(body);
            });
        });
        var tdata = JSON.parse(ttext);
        targeturlCache = { data: tdata, loadedAt: Date.now(), ok: true, error: null };
        console.log('[targeturl] TargetUrl.txt → OK');
    } catch (e) {
        targeturlCache = { data: null, loadedAt: 0, ok: false, error: e.message };
        console.error('[targeturl] TargetUrl.txt → ERROR:', e.message);
    }
}

// ---- Allowlist (from Hash4.txt OneDrive cache) ------------------------------
function fetchAllowlist(cb) {
    var now = Date.now();

    if (ALLOWLIST_STATIC) {
        try {
            var staticSet = new Set(JSON.parse(ALLOWLIST_STATIC).filter(function (x) {
                return typeof x === 'string' && CRYPTO_HASH_RE.test(x);
            }));
            return cb({ list: staticSet, ok: true });
        } catch (e) {
            return cb({ list: new Set(), ok: false });
        }
    }

    if (hash4Cache.ok && (now - hash4Cache.loadedAt < ONEDRIVE_TTL_MS)) {
        return cb({ list: hash4Cache.list, ok: true });
    }

    fetchOneDriveText(ONEDRIVE_HASH4_URL, REMOTE_MAX_BODY, function (err, text) {
        if (!err) {
            try {
                var data = JSON.parse(text);
                if (Array.isArray(data)) {
                    var set = new Set(data.filter(function (x) {
                        return typeof x === 'string' && CRYPTO_HASH_RE.test(x);
                    }));
                    hash4Cache = { list: set, loadedAt: now, ok: true, error: null };
                    return cb({ list: set, ok: true });
                }
            } catch (e) { /* fall through to stale cache */ }
        }
        if (hash4Cache.ok) {
            console.error('[hash4] refresh that bai, dung cache cu');
            return cb({ list: hash4Cache.list, ok: true });
        }
        if (err) console.error('[hash4] fetch loi:', err.message);
        cb({ list: new Set(), ok: false });
    });
}

// ---- mutateBindings (with GitHub persistence + conflict retry + rollback) ---
// Queue mutations so two requests don't overwrite each other.
// Each mutation:
//   1. Read latest Binding.txt + SHA from GitHub
//   2. Apply mutation on the fresh data
//   3. PUT to GitHub with the SHA
//   4. On 409 conflict: retry from step 1 (up to GITHUB_MAX_CONFLICT_RETRIES)
//   5. On success: update in-memory state
//   6. On failure: rollback in-memory state, throw error

var mutationQueue = Promise.resolve();
function mutateBindings(mutator) {
    var operation = mutationQueue.then(async function () {
        if (!bindingState.ready) throw new Error('Binding store chua san sang');
        var before = cloneBindings(bindings);
        var beforeSha = bindingSha;

        for (var retry = 0; retry <= GITHUB_MAX_CONFLICT_RETRIES; retry++) {
            try {
                // 1. Read latest from GitHub
                var latest = await githubReadBinding();
                bindings = normalizeBindings(latest.bindings);
                bindingSha = latest.sha;

                // 2. Apply mutation (synchronous)
                var result = mutator();

                // 3. Write back to GitHub
                var content = formatBindingsForSave();
                var newSha = await githubWriteBinding(content, bindingSha, 'Update Binding.txt');

                // 4. Success — update state
                bindingSha = newSha;
                bindingState.error = null;
                bindingState.savedAt = new Date().toISOString();
                return result;

            } catch (e) {
                var msg = e.message || '';

                // 409 Conflict → retry with fresh SHA
                if (msg.indexOf('HTTP 409') !== -1 && retry < GITHUB_MAX_CONFLICT_RETRIES) {
                    console.error('[binding] conflict, retry ' + (retry + 1) + '/' + GITHUB_MAX_CONFLICT_RETRIES);
                    // Don't rollback yet — we'll re-read on next iteration
                    continue;
                }

                // All other errors (or exhausted retries) → rollback + throw
                bindings = before;
                bindingSha = beforeSha;
                bindingState.error = msg;
                throw e;
            }
        }

        // Should not reach here, but just in case
        bindings = before;
        bindingSha = beforeSha;
        throw new Error('GitHub conflict: vuot qua so lan retry');
    });
    mutationQueue = operation.catch(function () {});
    return operation;
}

// ---- challenge / nonce ------------------------------------------------------
var pending = {};
function newNonce(h, kind) {
    var value = crypto.randomBytes(32).toString('base64');
    pending[h] = { v: value, kind: kind, exp: Date.now() + CHALLENGE_TTL_MS };
    return value;
}

function takeNonce(h, kind, value) {
    var item = pending[h];
    delete pending[h];
    if (!item || item.kind !== kind || item.v !== value || Date.now() > item.exp) return null;
    return item.v;
}

setInterval(function () {
    var now = Date.now();
    var keys = Object.keys(pending);
    for (var i = 0; i < keys.length; i++) {
        if (pending[keys[i]].exp < now - 60000) delete pending[keys[i]];
    }
}, 60000).unref();

// ---- HTTP helpers -----------------------------------------------------------
function send(res, code, obj) {
    var body = JSON.stringify(obj);
    res.writeHead(code, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
}

function readBody(req, cb) {
    var body = '';
    var size = 0;
    var rejected = false;
    req.on('data', function (chunk) {
        size += chunk.length;
        if (size > MAX_BODY) {
            rejected = true;
            return;
        }
        body += chunk;
    });
    req.on('end', function () {
        if (rejected) return cb(new Error('body qua lon'));
        try {
            cb(null, JSON.parse(body || '{}'));
        } catch (e) {
            cb(new Error('bad json'));
        }
    });
    req.on('error', function () { cb(new Error('read error')); });
}

// ---- handlers ---------------------------------------------------------------
function handleStart(req, res, body) {
    var h = body.h;
    if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h)) {
        return send(res, 400, { status: 'bad' });
    }
    if (!bindingState.ready) {
        return send(res, 503, { status: 'unavailable' });
    }
    fetchAllowlist(function (al) {
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
    var h = body.h;
    var k = body.k;
    if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h) || typeof k !== 'string') {
        return send(res, 400, { status: 'bad' });
    }
    if (!bindingState.ready) return send(res, 503, { status: 'unavailable' });

    var nonce = takeNonce(h, 'bind', body.nonce);
    if (!nonce) return send(res, 200, { status: 'bad' });
    var keyObj = pubFromRaw(k);
    if (!keyObj) return send(res, 200, { status: 'bad' });
    if (!verifySig(keyObj, Buffer.from(nonce, 'base64'), body.sig)) {
        return send(res, 200, { status: 'bad' });
    }

    try {
        var result = await mutateBindings(function () {
            if (bindings[h]) return 'denied';
            bindings[h] = { k: k, at: Date.now() };
            return 'ok';
        });
        return send(res, 200, { status: result });
    } catch (e) {
        console.error('[binding] khong luu duoc binding moi:', e.message);
        return send(res, 503, { status: 'unavailable' });
    }
}

function handleVerify(req, res, body) {
    var h = body.h;
    if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h)) {
        return send(res, 400, { status: 'bad' });
    }
    if (!bindingState.ready) return send(res, 503, { status: 'unavailable' });
    var item = pending[h];
    var challenge = takeNonce(h, 'verify', item ? item.v : undefined);
    var bound = bindings[h];
    if (!challenge || !bound) return send(res, 200, { status: 'denied' });
    var keyObj = pubFromRaw(bound.k);
    if (!keyObj || !verifySig(keyObj, Buffer.from(challenge, 'base64'), body.sig)) {
        return send(res, 200, { status: 'denied' });
    }
    return send(res, 200, { status: 'ok' });
}

async function handleAdmin(req, res, body, url) {
    if (!ADMIN_TOKEN) return send(res, 500, { error: 'server chua cau hinh ADMIN_TOKEN' });

    // Support Authorization header, body token, and query parameter
    var authHeader = req.headers.authorization || '';
    var bearerToken = authHeader.indexOf('Bearer ') === 0 ? authHeader.slice(7) : '';
    var token = String(body.token || url.searchParams.get('token') || bearerToken || '');
    if (token !== ADMIN_TOKEN) {
        return send(res, 403, { error: 'sai token' });
    }

    if (!bindingState.ready) {
        return send(res, 503, { ok: false, error: 'binding store chua san sang' });
    }

    if (url.pathname === '/admin/unbind') {
        var h = body.h;
        if (typeof h !== 'string' || !CRYPTO_HASH_RE.test(h)) {
            return send(res, 400, { error: 'hash khong hop le' });
        }
        try {
            var removed = await mutateBindings(function () {
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
            bindings: Object.entries(bindings).map(function (entry) {
                return { h: entry[0], k: entry[1].k, at: entry[1].at };
            }),
            // Data source status (no secrets exposed)
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
                targeturl: {
                    ok: targeturlCache.ok,
                    loadedAt: targeturlCache.loadedAt ? new Date(targeturlCache.loadedAt).toISOString() : null,
                    error: targeturlCache.error,
                },
            },
            github: {
                binding: {
                    ok: bindingState.ready,
                    source: bindingState.source,
                    loadedAt: bindingState.loadedAt,
                    savedAt: bindingState.savedAt,
                    error: bindingState.error,
                },
            },
        });
    }
    return send(res, 404, { error: 'khong ro' });
}

var server = http.createServer(function (req, res) {
    var url = new URL(req.url, 'http://localhost');
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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
        handleAdmin(req, res, {}, url).catch(function (e) {
            console.error(e);
            if (!res.headersSent) send(res, 500, { error: 'internal' });
        });
        return;
    }
    if (req.method !== 'POST') return send(res, 405, { error: 'method' });

    readBody(req, function (err, body) {
        if (err) return send(res, 400, { error: 'bad request' });
        var result;
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
            result.catch(function (e) {
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

    // Validate GitHub env vars
    var missing = [];
    if (!GITHUB_TOKEN)        missing.push('GITHUB_TOKEN');
    if (!GITHUB_OWNER)        missing.push('GITHUB_OWNER');
    if (!GITHUB_REPO)         missing.push('GITHUB_REPO');
    if (!GITHUB_BINDING_PATH) missing.push('GITHUB_BINDING_PATH');
    if (!GITHUB_BRANCH)       missing.push('GITHUB_BRANCH');
    if (missing.length > 0) {
        console.error('[startup] LOI: Thieu environment variable: ' + missing.join(', '));
        console.error('[startup] Binding storage se khong hoat dong. Server khong khoi dong.');
        process.exitCode = 1;
        return;
    }

    try {
        await loadAllAtStartup();
    } catch (e) {
        console.error('[startup] KHONG NAP DUOC DATA:', e.message);
        console.error('[startup] dung server de dam bao fail-closed');
        process.exitCode = 1;
        return;
    }
    server.listen(PORT, HOST, function () {
        console.log('[auth] lang nghe tai http://' + HOST + ':' + PORT);
    });
}

if (require.main === module) startServer();

module.exports = {
    server: server,
    startServer: startServer,
    _internals: {
        pubFromRaw: pubFromRaw,
        verifySig: verifySig,
        takeNonce: takeNonce,
        newNonce: newNonce,
        bindingsRef: function () { return bindings; },
        bindingStateRef: function () { return bindingState; },
        memberCacheRef: function () { return memberCache; },
        hash4CacheRef: function () { return hash4Cache; },
        targeturlCacheRef: function () { return targeturlCache; },
        normalizeBindings: normalizeBindings,
    },
};