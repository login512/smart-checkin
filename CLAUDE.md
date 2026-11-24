# AI Agent Guide — Login512 Smart Check-in

When customizing or extending this repository with an AI coding agent (Cursor, Claude Code, Antigravity, Windsurf), preserve these non-negotiable security invariants:

1. **Never expose `LOGIN512_SECRET_KEY` (`l512_sk_...`)** to `public/` files, client-side JavaScript, or `/api/config`.
2. **Never trust client callbacks alone.** Every authentication and check-in MUST pass through `src/login512/client.js` -> `POST /v1/token/verify` on the server and reject whenever `valid !== true`, `session_allowed !== true`, or `step_up_required === true`.
3. **Preserve Face vs Passkey verification contracts:**
   - Face logins MUST bind to a server-issued single-use `expected_nonce`.
   - Passkey logins MUST assert `claims.mod === 'PASSKEY'` so a face token cannot bypass `expected_nonce`.
4. **Never store raw face photos or frames** in SQLite, disk, or logs (Zero-Image Persistence).
5. **Never trust browser GPS as cryptographic proof.** Proof of presence relies on server-signed rotating Dynamic QR (`5-8s`) + optional server-enforced Wi-Fi IP Allowlist (`src/login512/qr-guard.js`).
6. **Keep `DEMO_MOCK_AUTH=false` in production.** Do not remove the startup guard (`assertDemoMockAllowed` in `src/server.js`), the loopback-only check on `/api/demo/mock-token`, or the per-process random mock key in `client.js`.
7. **Keep CSRF protection** (`x-csrf-token`) on all state-changing `/api/admin/*` routes and rotate session IDs on login.
8. **Maintain `src/login512/` as clean, minimal reference code** (3 files: `client.js`, `qr-guard.js`, `genesis.js`) so developers can copy the pattern cleanly into other systems.
