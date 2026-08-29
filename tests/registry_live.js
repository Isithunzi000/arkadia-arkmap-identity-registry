'use strict';
// E2E LIVE rejestru — reczny (wymaga sieci; NIE jest czescia bramki CI).
// Rejestruje swiezy testowy nick, sprawdza idempotencje/konflikty, uniewaznia
// i weryfikuje tombstone na odczycie publicznym (raw.githubusercontent).
// Uruchom: node tests/registry_live.js
// Uwaga sandbox: DNS dla vercel.app bywa zatruty — obejscie przez lookup anycast.
const https = require('node:https');
const { webcrypto } = require('node:crypto');

const API_HOST = 'arkmap-identity-registry.vercel.app';
const VERCEL_ANYCAST = '76.76.21.21';
const RAW_URL = 'https://raw.githubusercontent.com/Isithunzi000/arkadia-arkmap-identity-registry/main/entries/';

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  OK   ' + msg); }
  else { fail++; console.log('  FAIL ' + msg); }
}

function apiPost(pathname, body) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: API_HOST, port: 443, path: pathname, method: 'POST',
      servername: API_HOST,
      lookup: (hostname, opts, cb) => (opts && opts.all)
        ? cb(null, [{ address: VERCEL_ANYCAST, family: 4 }])
        : cb(null, VERCEL_ANYCAST, 4),
      headers: { 'Content-Type': 'application/json' },
      timeout: 20000,
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) {}
        resolve({ code: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.end(JSON.stringify(body));
  });
}

async function rawEntry(nick) {
  const r = await fetch(RAW_URL + nick + '.json');
  if (r.status === 404) return { status: 404 };
  return { status: r.status, entry: await r.json() };
}

const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

(async () => {
  const nick = 'e2e' + Date.now().toString(36);
  console.log('nick testowy: ' + nick);

  // Klucze + PoP po stronie "klienta"
  const kp = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = Buffer.from(await webcrypto.subtle.exportKey('raw', kp.publicKey)).toString('hex');
  const { createHash } = require('node:crypto');
  const authorId = createHash('sha256').update(Buffer.from(pub, 'hex')).digest('hex').slice(0, 16);
  const sign = (msg) => webcrypto.subtle.sign('Ed25519', kp.privateKey, Buffer.from(msg, 'utf8'))
    .then((s) => Buffer.from(s).toString('hex'));

  // 1. rejestracja
  const sig = await sign('arkmap-registry-v1:register:' + nick + ':' + pub);
  const r1 = await apiPost('/api/register', { nick, pubkey: pub, author_id: authorId, sig });
  ok(r1.code === 201 && r1.json && r1.json.status === 'registered', 'rejestracja -> 201 registered');

  // 2. idempotencja
  const r2 = await apiPost('/api/register', { nick, pubkey: pub, author_id: authorId, sig });
  ok(r2.code === 200 && r2.json && r2.json.status === 'already', 'ponowna rejestracja -> 200 already');

  // 3. odczyt publiczny (raw CDN trzyma cache do ~5 min — probuj do 6,5 min)
  let seen = null;
  for (let i = 0; i < 20; i++) {
    seen = await rawEntry(nick);
    if (seen.status === 200 && seen.entry && seen.entry.pubkey === pub) break;
    await new Promise((r) => setTimeout(r, 20000));
  }
  ok(seen && seen.status === 200 && seen.entry.pubkey === pub && seen.entry.revoked === false
    && seen.entry.author_id === authorId,
    'odczyt publiczny: wpis z kluczem, revoked=false (to widzi aplikacja przy weryfikacji)');

  // 4. konflikt: cudzy klucz pod ten sam nick
  const kp2 = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub2 = Buffer.from(await webcrypto.subtle.exportKey('raw', kp2.publicKey)).toString('hex');
  const authorId2 = createHash('sha256').update(Buffer.from(pub2, 'hex')).digest('hex').slice(0, 16);
  const sig2 = await webcrypto.subtle.sign('Ed25519', kp2.privateKey,
    Buffer.from('arkmap-registry-v1:register:' + nick + ':' + pub2, 'utf8')).then((s) => Buffer.from(s).toString('hex'));
  const r4 = await apiPost('/api/register', { nick, pubkey: pub2, author_id: authorId2, sig: sig2 });
  ok(r4.code === 409 && r4.json && r4.json.error === 'nick_taken', 'cudzy klucz pod zajety nick -> 409 nick_taken');

  // 5. uniewaznienie cudzym kluczem -> 403
  const badRev = await webcrypto.subtle.sign('Ed25519', kp2.privateKey,
    Buffer.from('arkmap-registry-v1:revoke:' + nick, 'utf8')).then((s) => Buffer.from(s).toString('hex'));
  const r5 = await apiPost('/api/revoke', { nick, sig: badRev });
  ok(r5.code === 403 && r5.json && r5.json.error === 'bad_revoke_sig', 'revoke cudzym kluczem -> 403 bad_revoke_sig');

  // 6. uniewaznienie wlasciwym kluczem
  const goodRev = await sign('arkmap-registry-v1:revoke:' + nick);
  const r6 = await apiPost('/api/revoke', { nick, sig: goodRev });
  ok(r6.code === 200 && r6.json && r6.json.status === 'revoked'
    && r6.json.entry && r6.json.entry.revoked === true && r6.json.entry.revoked_by === 'owner',
    'revoke wlasciciela -> 200 revoked, tombstone revoked_by=owner');

  // 7. powtorka -> idempotentne already_revoked
  const r7 = await apiPost('/api/revoke', { nick, sig: goodRev });
  ok(r7.code === 200 && r7.json && r7.json.status === 'already_revoked', 'powtorzony revoke -> already_revoked');

  // 8. wariant A: nick nie wraca do puli
  const r8 = await apiPost('/api/register', { nick, pubkey: pub, author_id: authorId, sig });
  ok(r8.code === 410 && r8.json && r8.json.error === 'nick_revoked', 'rejestracja po uniewaznieniu -> 410 nick_revoked');

  // 9. tombstone widoczny publicznie (po propagacji raw CDN — jak krok 3)
  let tomb = null;
  for (let i = 0; i < 20; i++) {
    tomb = await rawEntry(nick);
    if (tomb.status === 200 && tomb.entry && tomb.entry.revoked === true) break;
    await new Promise((r) => setTimeout(r, 20000));
  }
  ok(tomb && tomb.status === 200 && tomb.entry.revoked === true && typeof tomb.entry.revoke_sig === 'string',
    'odczyt publiczny: tombstone widoczny (to widzi aplikacja -> czerwone ostrzezenie)');

  console.log('\n═══ registry_live: ' + pass + ' OK, ' + fail + ' FAIL ═══');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('WYJATEK E2E:', e); process.exit(1); });
