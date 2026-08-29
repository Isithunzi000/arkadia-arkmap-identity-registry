'use strict';
// Rdzeń wspólny funkcji register/revoke. Czyste walidatory + handlery z
// wstrzykiwanymi zależnościami (ghRead/ghWrite/now/verify) — pokryte harness'em
// tests/registry_core.js. Warstwa HTTP (req/res) jest w plikach tras.

const { createHash, webcrypto } = require('node:crypto');

// ── Kontrakt (pin krzyżowy: tests/registry_core.js po stronie serwisu,
//    tests/registry_client.js po stronie aplikacji) ──────────────────────────
const NICK_RE = /^[a-z0-9]{1,32}$/;          // forma kanoniczna = lowercase (aplikacja kanonikalizuje PRZED wysyłką)
const PUBKEY_RE = /^[0-9a-f]{64}$/;          // Ed25519 raw public key, hex
const SIG_RE = /^[0-9a-f]{128}$/;            // Ed25519 signature, hex
const AUTHOR_ID_RE = /^[0-9a-f]{16}$/;       // pierwsze 16 hex SHA-256(pubkey)

const GH_OWNER = 'Isithunzi000';
const GH_REPO = 'arkadia-arkmap-identity-registry';
const GH_BRANCH = 'main';
const ENTRY_PREFIX = 'entries';

function registerPayload(nick, pubkeyHex) {
  return 'arkmap-registry-v1:register:' + nick + ':' + pubkeyHex;
}
function revokePayload(nick) {
  return 'arkmap-registry-v1:revoke:' + nick;
}
function entryPath(nick) {
  return ENTRY_PREFIX + '/' + nick + '.json';
}
function authorIdOf(pubkeyHex) {
  return createHash('sha256').update(Buffer.from(pubkeyHex, 'hex')).digest('hex').slice(0, 16);
}

// ── Walidatory kształtu ─────────────────────────────────────────────────────
function isHex(s, n) { return typeof s === 'string' && new RegExp('^[0-9a-f]{' + n + '}$').test(s); }

function validateRegisterBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'body';
  if (typeof body.nick !== 'string' || !NICK_RE.test(body.nick)) return 'nick';
  if (!isHex(body.pubkey, 64)) return 'pubkey';
  if (!isHex(body.author_id, 16)) return 'author_id';
  if (!isHex(body.sig, 128)) return 'sig';
  return null;
}
function validateRevokeBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'body';
  if (typeof body.nick !== 'string' || !NICK_RE.test(body.nick)) return 'nick';
  if (!isHex(body.sig, 128)) return 'sig';
  return null;
}

// ── Krypto (Node 20 webcrypto, Ed25519) ─────────────────────────────────────
async function ed25519Verify(pubkeyHex, sigHex, message) {
  try {
    const key = await webcrypto.subtle.importKey('raw', Buffer.from(pubkeyHex, 'hex'), { name: 'Ed25519' }, false, ['verify']);
    return await webcrypto.subtle.verify('Ed25519', key, Buffer.from(sigHex, 'hex'), Buffer.from(message, 'utf8'));
  } catch (e) {
    return false;  // zdeformowany klucz/podpis = po prostu nieważny dowód
  }
}

// ── GitHub Contents API (zapis atomowy per-plik: sha + bounded retry) ───────
async function ghReadEntry(token, nick) {
  const r = await fetch('https://api.github.com/repos/' + GH_OWNER + '/' + GH_REPO + '/contents/'
    + entryPath(nick) + '?ref=' + GH_BRANCH, {
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'User-Agent': 'arkmap-registry' },
  });
  if (r.status === 404) return { status: 404 };
  if (!r.ok) return { status: r.status };
  const d = await r.json();
  const text = Buffer.from(d.content, 'base64').toString('utf8');
  let entry = null;
  try { entry = JSON.parse(text); } catch (e) { return { status: 422, corrupt: true }; }
  return { status: 200, sha: d.sha, entry };
}

async function ghWriteEntry(token, nick, entry, sha, message) {
  const body = {
    message,
    content: Buffer.from(JSON.stringify(entry, null, 2) + '\n', 'utf8').toString('base64'),
    branch: GH_BRANCH,
  };
  if (sha) body.sha = sha;
  const r = await fetch('https://api.github.com/repos/' + GH_OWNER + '/' + GH_REPO + '/contents/'
    + entryPath(nick), {
    method: 'PUT',
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'User-Agent': 'arkmap-registry' },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, status: r.status };
}

// ── Handler rejestracji (czysta logika; deps wstrzyknięte) ──────────────────
// deps: { token, now() -> ISO, read(nick) -> {status, sha?, entry?}, write(nick, entry, sha, msg) -> {ok, status} }
async function handleRegister(deps, body) {
  const bad = validateRegisterBody(body);
  if (bad) return { code: 400, json: { error: 'invalid_' + bad } };

  const { nick, pubkey, author_id, sig } = body;
  if (author_id !== authorIdOf(pubkey)) return { code: 400, json: { error: 'author_id_mismatch' } };
  if (!(await ed25519Verify(pubkey, sig, registerPayload(nick, pubkey)))) {
    return { code: 403, json: { error: 'bad_pop' } };  // brak dowodu posiadania klucza prywatnego
  }

  // Atomowość: read -> decyzja -> write ze sha; konflikt -> odczyt ponowny (max 3).
  for (let attempt = 0; attempt < 3; attempt++) {
    const cur = await deps.read(nick);
    if (cur.status === 404) {
      const entry = {
        version: 1,
        nick,
        author_id,
        pubkey,
        registered_at: deps.now(),
        register_sig: sig,
        revoked: false,
        revoked_at: null,
        revoke_sig: null,
        revoked_by: null,
      };
      const w = await deps.write(nick, entry, null, 'register ' + nick);
      if (w.ok) return { code: 201, json: { status: 'registered', entry } };
      if (w.status === 409 || w.status === 422) continue;  // wyścig o utworzenie — odczytaj jeszcze raz
      return { code: 502, json: { error: 'registry_write_failed' } };
    }
    if (cur.status !== 200) return { code: 502, json: { error: 'registry_read_failed' } };
    const e = cur.entry;
    if (e.revoked) return { code: 410, json: { error: 'nick_revoked' } };              // wariant A: nick unieważniony na zawsze
    if (e.pubkey === pubkey) return { code: 200, json: { status: 'already', entry: e } }; // idempotencja
    return { code: 409, json: { error: 'nick_taken' } };
  }
  return { code: 409, json: { error: 'registry_contended' } };
}

// ── Handler unieważnienia ───────────────────────────────────────────────────
async function handleRevoke(deps, body) {
  const bad = validateRevokeBody(body);
  if (bad) return { code: 400, json: { error: 'invalid_' + bad } };

  const { nick, sig } = body;
  for (let attempt = 0; attempt < 3; attempt++) {
    const cur = await deps.read(nick);
    if (cur.status === 404) return { code: 404, json: { error: 'not_registered' } };
    if (cur.status !== 200) return { code: 502, json: { error: 'registry_read_failed' } };
    const e = cur.entry;
    if (e.revoked) return { code: 200, json: { status: 'already_revoked', entry: e } };  // idempotencja
    // Podpis weryfikowany względem klucza Z REJESTRU (nigdy z żądania) — właściciel lub nikt.
    if (!(await ed25519Verify(e.pubkey, sig, revokePayload(nick)))) {
      return { code: 403, json: { error: 'bad_revoke_sig' } };
    }
    const tombstone = Object.assign({}, e, {
      revoked: true,
      revoked_at: deps.now(),
      revoke_sig: sig,
      revoked_by: 'owner',
    });
    const w = await deps.write(nick, tombstone, cur.sha, 'revoke ' + nick);
    if (w.ok) return { code: 200, json: { status: 'revoked', entry: tombstone } };
    if (w.status === 409 || w.status === 422) continue;
    return { code: 502, json: { error: 'registry_write_failed' } };
  }
  return { code: 409, json: { error: 'registry_contended' } };
}

// ── Rate limit (best-effort, per-instancja serverless; twardym limitem jest
//    serializacja na GitHub API) ─────────────────────────────────────────────
const _rl = new Map();
function rateLimitHit(key, limit, windowMs, nowMs) {
  const now = nowMs || Date.now();
  let arr = _rl.get(key);
  if (!arr) { arr = []; _rl.set(key, arr); }
  while (arr.length && now - arr[0] > windowMs) arr.shift();
  if (arr.length >= limit) return true;
  arr.push(now);
  if (_rl.size > 10000) _rl.clear();  // higiena pamięci przy floodzie losowych kluczy
  return false;
}

module.exports = {
  NICK_RE, PUBKEY_RE, SIG_RE, AUTHOR_ID_RE,
  GH_OWNER, GH_REPO, GH_BRANCH, ENTRY_PREFIX,
  registerPayload, revokePayload, entryPath, authorIdOf,
  validateRegisterBody, validateRevokeBody, ed25519Verify,
  ghReadEntry, ghWriteEntry, handleRegister, handleRevoke, rateLimitHit,
};
