# ArkMap Identity Registry

Publiczny rejestr nicków tożsamości [ArkMap Studio](https://github.com/Isithunzi000/arkadia-web_standalone-arkmap_studio)
(formaty `.arkmap` / `.arkdelta`, podpisy Ed25519, spec: `docs/arkdelta_spec.html` §9).

**Odczyt jest publiczny** (klient czyta pliki prosto z `raw.githubusercontent.com`).
**Zapis** (rejestracja / unieważnienie) idzie wyłącznie przez gateway serverless
(Vercel, `api/register.js` + `api/revoke.js`) — token zapisu do tego repo nigdy
nie opuszcza serwera.

## Wpis `entries/<nick>.json`

```json
{
  "version": 1,
  "nick": "zbyszek",
  "author_id": "cb4b9b4a5514412d",
  "pubkey": "<64 hex Ed25519>",
  "registered_at": "<ISO-8601>",
  "register_sig": "<128 hex>",
  "revoked": false,
  "revoked_at": null,
  "revoke_sig": null,
  "revoked_by": null
}
```

- `nick` — forma kanoniczna: `^[a-z0-9]{1,32}$` (lowercase; klient kanonikalizuje przed wysyłką).
- `author_id` — pierwsze 16 hex SHA-256 nad bajtami klucza publicznego.
- `register_sig` — Ed25519 PoP nad `'arkmap-registry-v1:register:' + nick + ':' + pubkey`.
- Unieważnienie = tombstone: `revoked: true`, `revoked_at`, `revoke_sig`
  (Ed25519 nad `'arkmap-registry-v1:revoke:' + nick`, weryfikowany względem klucza
  **z rejestru**), `revoked_by: "owner"`. Klucze zostają w tombstone do audytu.
- **Wariant A:** unieważniony nick nigdy nie wraca do puli (ponowna rejestracja → `410 nick_revoked`).

## API gateway

| Endpoint | Body | Odpowiedzi |
|---|---|---|
| `POST /api/register` | `{nick, pubkey, author_id, sig}` | `201 registered` · `200 already` · `400 invalid_*` / `author_id_mismatch` · `403 bad_pop` · `409 nick_taken` · `410 nick_revoked` |
| `POST /api/revoke` | `{nick, sig}` | `200 revoked` / `already_revoked` · `400 invalid_*` · `403 bad_revoke_sig` · `404 not_registered` |

Obie operacje idempotentne (bezpieczny retry po timeoutcie). Rate limit best-effort
per IP; twardą serializacją zapisu jest GitHub Contents API (sha + bounded retry).

## Testy

```bash
node tests/registry_core.js   # 28 asercji: kontrakt, PoP, idempotencja, tombstone, wyścigi, rate limit
```
