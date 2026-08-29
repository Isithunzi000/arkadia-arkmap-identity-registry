'use strict';
// POST /api/revoke — unieważnienie nicku (tombstone; wariant A: nick nigdy
// nie wraca do puli). Body: { nick, sig } — sig = Ed25519 nad revokePayload,
// weryfikowany względem klucza Z REJESTRU. Idempotentne.
// Odpowiedzi: 200 revoked | 200 already_revoked | 400 invalid_*
//             | 403 bad_revoke_sig | 404 not_registered | 429 | 502 registry_*
const core = require('./_core.js');

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (core.rateLimitHit('rev:' + ip, 10, 60000)) { res.status(429).json({ error: 'rate_limited' }); return; }

  const token = process.env.GITHUB_REGISTRY_TOKEN;
  if (!token) { res.status(500).json({ error: 'misconfigured' }); return; }

  const deps = {
    token,
    now: () => new Date().toISOString(),
    read: (nick) => core.ghReadEntry(token, nick),
    write: (nick, entry, sha, msg) => core.ghWriteEntry(token, nick, entry, sha, msg),
  };

  try {
    const r = await core.handleRevoke(deps, req.body);
    res.status(r.code).json(r.json);
  } catch (e) {
    res.status(500).json({ error: 'internal' });
  }
};
