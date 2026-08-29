'use strict';
// Harness logiki rdzenia rejestru (api/_core.js) — prawdziwe klucze Ed25519
// (webcrypto), zamockowane GitHub Contents API w pamięci. Uruchom: node tests/registry_core.js
const { webcrypto } = require('node:crypto');
const path = require('path');
const core = require(path.join(__dirname, '..', 'api', '_core.js'));

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  OK   ' + msg); }
  else { fail++; console.log('  FAIL ' + msg); }
}

// ── Mock magazynu entries/<nick>.json (read/write z sha, konflikty jak Contents API) ──
function mkStore() {
  const files = new Map();  // nick -> { sha, entry }
  let seq = 0;
  return {
    files,
    read: async (nick) => {
      const f = files.get(nick);
      return f ? { status: 200, sha: f.sha, entry: JSON.parse(JSON.stringify(f.entry)) } : { status: 404 };
    },
    write: async (nick, entry, sha, msg) => {
      const f = files.get(nick);
      if (f && sha !== f.sha) return { ok: false, status: 409 };      // sha mismatch jak w Contents API
      if (!f && sha) return { ok: false, status: 422 };
      files.set(nick, { sha: 'sha' + (++seq), entry: JSON.parse(JSON.stringify(entry)) });
      return { ok: true, status: f ? 200 : 201 };
    },
  };
}

async function mkIdentity(nick) {
  const kp = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = Buffer.from(await webcrypto.subtle.exportKey('raw', kp.publicKey)).toString('hex');
  const sign = async (msg) => Buffer.from(await webcrypto.subtle.sign('Ed25519', kp.privateKey, Buffer.from(msg, 'utf8'))).toString('hex');
  return { nick, pubkey: pub, author_id: core.authorIdOf(pub), sign };
}

const NOW = () => '2026-08-29T00:00:00.000Z';
const depsFor = (store) => ({
  token: 'T', now: NOW,
  read: store.read, write: store.write,
});

(async () => {
  // ── T0: kontrakt — piny statyczne (krzyżowe z tests/registry_client.js w apce) ──
  ok(core.registerPayload('zbyszek', 'ab') === 'arkmap-registry-v1:register:zbyszek:ab',
    'T0: registerPayload — domena arkmap-registry-v1:register:');
  ok(core.revokePayload('zbyszek') === 'arkmap-registry-v1:revoke:zbyszek',
    'T0: revokePayload — domena arkmap-registry-v1:revoke:');
  ok(core.entryPath('ala9') === 'entries/ala9.json', 'T0: entryPath entries/<nick>.json');
  ok(core.GH_OWNER === 'Isithunzi000' && core.GH_REPO === 'arkadia-arkmap-identity-registry' && core.GH_BRANCH === 'main',
    'T0: repo rejestru przypięte (Isithunzi000/arkadia-arkmap-identity-registry@main)');
  ok(core.NICK_RE.test('zbyszek09') && !core.NICK_RE.test('Zbyszek') && !core.NICK_RE.test('zby szek')
    && !core.NICK_RE.test('zbyś') && !core.NICK_RE.test('') && !core.NICK_RE.test('a'.repeat(33)),
    'T0: charset nicku [a-z0-9]{1,32}, wyłącznie forma kanoniczna (lowercase)');

  // ── T1: walidacja kształtu body ──
  ok(core.validateRegisterBody(null) === 'body' && core.validateRegisterBody([]) === 'body',
    'T1: register body nieobiektowe -> invalid_body');
  ok(core.validateRegisterBody({ nick: 'Z', pubkey: 'a'.repeat(64), author_id: 'b'.repeat(16), sig: 'c'.repeat(128) }) === 'nick',
    'T1: wielka litera w nicku -> invalid_nick (kanonikalizacja jest po stronie klienta)');
  ok(core.validateRegisterBody({ nick: 'ok', pubkey: 'zz', author_id: 'b'.repeat(16), sig: 'c'.repeat(128) }) === 'pubkey',
    'T1: zły pubkey -> invalid_pubkey');
  ok(core.validateRevokeBody({ nick: 'ok' }) === 'sig', 'T1: revoke bez sig -> invalid_sig');

  // ── T2: author_id = first16(SHA-256(pubkey)) ──
  const idA = await mkIdentity('ala');
  ok(core.authorIdOf(idA.pubkey).length === 16 && /^[0-9a-f]{16}$/.test(core.authorIdOf(idA.pubkey)),
    'T2: author_id 16 hex z SHA-256 klucza');
  ok(core.authorIdOf(idA.pubkey) !== core.authorIdOf((await mkIdentity('x')).pubkey),
    'T2: różne klucze -> różne author_id');

  // ── T3: happy path rejestracji ──
  {
    const store = mkStore();
    const sig = await idA.sign(core.registerPayload('ala', idA.pubkey));
    const r = await core.handleRegister(depsFor(store), { nick: 'ala', pubkey: idA.pubkey, author_id: idA.author_id, sig });
    ok(r.code === 201 && r.json.status === 'registered', 'T3: rejestracja -> 201 registered');
    const e = store.files.get('ala').entry;
    ok(e.version === 1 && e.nick === 'ala' && e.pubkey === idA.pubkey && e.author_id === idA.author_id
      && e.registered_at === NOW() && e.register_sig === sig
      && e.revoked === false && e.revoked_at === null && e.revoke_sig === null && e.revoked_by === null,
      'T3: schema wpisu v1 kompletna (registered_at, register_sig, pola unieważnienia null)');

    // idempotencja: ta sama rejestracja ponownie
    const r2 = await core.handleRegister(depsFor(store), { nick: 'ala', pubkey: idA.pubkey, author_id: idA.author_id, sig });
    ok(r2.code === 200 && r2.json.status === 'already', 'T3: ponowna rejestracja tego samego -> 200 already (idempotencja)');
    ok(store.files.get('ala').entry.registered_at === NOW(), 'T3: already nie rusza wpisu');

    // nick zajęty przez inny klucz
    const idB = await mkIdentity('b');
    const sigB = await idB.sign(core.registerPayload('ala', idB.pubkey));
    const r3 = await core.handleRegister(depsFor(store), { nick: 'ala', pubkey: idB.pubkey, author_id: idB.author_id, sig: sigB });
    ok(r3.code === 409 && r3.json.error === 'nick_taken', 'T3: cudzy klucz pod zajęty nick -> 409 nick_taken');
  }

  // ── T4: PoP i author_id ──
  {
    const store = mkStore();
    const idC = await mkIdentity('c');
    const sigWrongNick = await idC.sign(core.registerPayload('inny', idC.pubkey));
    ok((await core.handleRegister(depsFor(store), { nick: 'cela', pubkey: idC.pubkey, author_id: idC.author_id, sig: sigWrongNick })).code === 403,
      'T4: PoP nad innym nickiem -> 403 bad_pop');
    const sigOk = await idC.sign(core.registerPayload('cela', idC.pubkey));
    ok((await core.handleRegister(depsFor(store), { nick: 'cela', pubkey: idC.pubkey, author_id: '0'.repeat(16), sig: sigOk })).json.error === 'author_id_mismatch',
      'T4: author_id != hash(pubkey) -> 400 author_id_mismatch (PoP nawet nie sprawdzany dalej)');
    const idD = await mkIdentity('d');
    const sigStolen = await idD.sign(core.registerPayload('celb', idC.pubkey));  // D podpisuje za klucz C
    ok((await core.handleRegister(depsFor(store), { nick: 'celb', pubkey: idC.pubkey, author_id: idC.author_id, sig: sigStolen })).code === 403,
      'T4: podpis cudzym kluczem prywatnym -> 403 bad_pop (brak posiadania)');
  }

  // ── T5: unieważnienie ──
  {
    const store = mkStore();
    const sig = await idA.sign(core.registerPayload('ewa', idA.pubkey));
    await core.handleRegister(depsFor(store), { nick: 'ewa', pubkey: idA.pubkey, author_id: idA.author_id, sig });

    ok((await core.handleRevoke(depsFor(store), { nick: 'nikt', sig: 'a'.repeat(128) })).code === 404,
      'T5: revoke niezarejestrowanego -> 404 not_registered');

    const badSig = await (await mkIdentity('z')).sign(core.revokePayload('ewa'));
    ok((await core.handleRevoke(depsFor(store), { nick: 'ewa', sig: badSig })).json.error === 'bad_revoke_sig',
      'T5: revoke cudzym kluczem -> 403 bad_revoke_sig (sig vs klucz Z REJESTRU)');

    const goodSig = await idA.sign(core.revokePayload('ewa'));
    const rr = await core.handleRevoke(depsFor(store), { nick: 'ewa', sig: goodSig });
    ok(rr.code === 200 && rr.json.status === 'revoked', 'T5: revoke właściciela -> 200 revoked');
    const e = store.files.get('ewa').entry;
    ok(e.revoked === true && e.revoked_at === NOW() && e.revoke_sig === goodSig && e.revoked_by === 'owner'
      && e.pubkey === idA.pubkey && e.author_id === idA.author_id,
      'T5: tombstone: revoked_at + revoke_sig + revoked_by=owner, klucze zachowane do audytu');

    const rr2 = await core.handleRevoke(depsFor(store), { nick: 'ewa', sig: goodSig });
    ok(rr2.code === 200 && rr2.json.status === 'already_revoked', 'T5: powtórzony revoke -> already_revoked (idempotencja)');

    const sig2 = await idA.sign(core.registerPayload('ewa', idA.pubkey));
    ok((await core.handleRegister(depsFor(store), { nick: 'ewa', pubkey: idA.pubkey, author_id: idA.author_id, sig: sig2 })).code === 410,
      'T5: rejestracja po unieważnieniu -> 410 nick_revoked (wariant A: nick nie wraca do puli)');
  }

  // ── T6: wyścig o zapis (sha mismatch) — retry z ponownym odczytem ──
  {
    const store = mkStore();
    const idE = await mkIdentity('e');
    const sig = await idE.sign(core.registerPayload('ola', idE.pubkey));
    // pierwsza próba write dostaje sha=null na istniejącym pliku -> 422 -> retry -> read widzi wpis -> already
    store.files.set('ola', { sha: 'shaX', entry: { version: 1, nick: 'ola', pubkey: idE.pubkey, author_id: idE.author_id, revoked: false } });
    // symulacja: read zwraca 404 na pierwszą próbę (stary widok), potem realny stan
    let reads = 0;
    const deps = depsFor(store);
    const origRead = deps.read;
    deps.read = async (n) => (++reads === 1 ? { status: 404 } : origRead(n));
    const r = await core.handleRegister(deps, { nick: 'ola', pubkey: idE.pubkey, author_id: idE.author_id, sig });
    ok(r.code === 200 && r.json.status === 'already' && reads >= 2,
      'T6: konflikt zapisu -> ponowny odczyt -> zgodność -> already (bounded retry)');
  }

  // ── T7: rate limiter ──
  ok(!core.rateLimitHit('t7', 2, 60000, 1000) && !core.rateLimitHit('t7', 2, 60000, 1001)
    && core.rateLimitHit('t7', 2, 60000, 1002),
    'T7: trzecie żądanie w oknie -> limited');
  ok(!core.rateLimitHit('t7', 2, 60000, 1000 + 61000), 'T7: po oknie limit znika');

  console.log('\n═══ registry_core: ' + pass + ' OK, ' + fail + ' FAIL ═══');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('WYJATEK HARNESSA:', e); process.exit(1); });
