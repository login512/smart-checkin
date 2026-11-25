# AGENTS.md — Login512 Smart Check-in

The guide for AI coding agents (Claude Code, Cursor, Codex, Gemini / Antigravity, GitHub Copilot, Windsurf) and for
people. `CLAUDE.md` and `GEMINI.md` point here.

Smart Check-in is a working check-in app **and** a reference for adding Login512 face / passkey login to any system.
One codebase serves 5 industries through **presets**; a new industry is one JSON file.

## Map

| Path | What it is |
|---|---|
| `src/login512/client.js` | The only place that talks to Login512: enrollment tokens, `POST /v1/token/verify`, nonce and method checks. Copy this pattern into other systems. |
| `src/login512/qr-guard.js` | Rotating HMAC-signed kiosk QR (5–8 s) and the optional on-site Wi-Fi IP allowlist. |
| `src/login512/genesis.js` | First-time setup: one-time setup key, first Superadmin, then locked forever. |
| `src/server.js` | Express routes: `/api/setup/*`, `/api/auth/*`, `/api/checkin/*`, `/api/admin/*`, `/api/kiosk/*`. |
| `src/presets.js` | Loads `presets/*.json` (5 built-ins first, then custom ones by id) and validates them. |
| `src/db.js` | SQLite (`node:sqlite`, Node 22.5+). |
| `presets/*.json` | Industries: `classroom`, `workplace`, `event`, `checkpoint`, `dev-reference`. |
| `public/` | `setup.html`, `kiosk.html`, `scan.html`, `admin.html`; shared code in `public/assets/i18n.js` (TH / EN). |
| `tests/smart-checkin.test.js` | `node --test`, offline (mock mode). |
| `docs/ADD_A_PRESET.md` | Step by step: add an industry. |

## Commands

```bash
npm install
npm test                 # all tests, offline
npm run check:presets    # validate presets/*.json (run after adding or editing a preset)
npm start                # http://localhost:3512 (needs Login512 keys in .env)
npm run build:zips       # one ready-to-run ZIP per preset in dist-zips/
```

## The 5 presets

| id | For | Notable |
|---|---|---|
| `classroom` | Classes, tutoring, exam rooms | Student ID + section, projector QR |
| `workplace` | Offices, shops, clinics, factories | Clock-in / clock-out, payroll CSV |
| `event` | Events, workshops, fitness, VIP | Live attendee counter on the kiosk |
| `checkpoint` | Security patrols, housekeeping, desks | 6 s QR, rounds with notes |
| `dev-reference` | Developers integrating Login512 | Opens the Token Verify Inspector |

## Extend it

- **New industry:** follow `docs/ADD_A_PRESET.md` (copy a preset, change `id` = file name, rewrite the TH / EN texts,
  `npm run check:presets`, `npm test`). No code change is needed.
- **Change wording of an industry:** edit that preset's `th` / `en` texts only.
- **Add a field to every preset:** add it to all files in `presets/`, read it in `public/` or `src/server.js`, and add
  it to `validatePreset` in `src/presets.js` only if every preset must have it.
- **Use the Login512 integration in another system (ERP, POS, LMS, SaaS):** copy `src/login512/client.js` and keep
  the rules below. The Login512 MCP tool `login512_smart_checkin` returns the same map for AI agents.

## Rules that must not be broken

1. **Never expose `LOGIN512_SECRET_KEY` (`l512_sk_...`)** to `public/` files, browser JavaScript or `/api/config`.
2. **Never trust browser callbacks alone.** Every login and check-in goes through `src/login512/client.js` →
   `POST /v1/token/verify` on the server and is rejected unless `valid === true`, `session_allowed === true` and
   `step_up_required !== true`.
3. **Face vs passkey:** face logins are bound to a server-issued single-use `expected_nonce`; passkey logins must have
   `claims.mod === 'PASSKEY'` so a face token can never skip the nonce.
4. **Never store face photos or frames** in SQLite, on disk or in logs.
5. **Never use browser GPS as proof of presence.** Presence = the rotating signed QR (5–8 s, `defaultQrRotateSec`)
   plus the optional Wi-Fi IP allowlist.
6. **Keep `DEMO_MOCK_AUTH=false` in production.** Do not remove the startup guard (`assertDemoMockAllowed` in
   `src/server.js`), the loopback-only check on `/api/demo/mock-token`, or the per-process random mock key.
7. **Keep CSRF protection** (`x-csrf-token`) on every state-changing `/api/admin/*` route; rotate the session on login.
8. **Keep `src/login512/` to its 3 small files** so others can copy the pattern.
9. **Setup on a second install** of the same Login512 account logs the existing Superadmin in (nonce-bound, same id
   only) instead of enrolling again. Keep that check (`/api/setup/claim`, `mode: login`).

## Before you finish

- `npm test` passes and `npm run check:presets` reports no problems.
- No `.env`, `data/`, `dist-zips/` or keys in what you commit.
- On a server behind a proxy: `HOST=127.0.0.1`, `TRUST_PROXY=1`, `PUBLIC_BASE_URL=https://your-domain`, and add that
  domain to **Allowed Origins** in the Login512 Portal.
