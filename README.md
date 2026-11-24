# Login512 Smart Check-in (Open-Source Proof-of-Presence & Reference App)

> **1 Clean Codebase • 5 Ready-to-Use Industry Presets • Pure-Web Dynamic QR (5–8s) + Optional Wi-Fi IP Allowlist • NIST ML-DSA-65 & Zero-Image Biometrics**

This repository is the official open-source **Reference Implementation** for [Login512](https://login512.com) — designed for two purposes at once:
1. **Ready-to-deploy check-in web app** across 5 industries with zero native app or App Store friction.
2. **Clean 3-file developer blueprint** (`src/login512/`) showing how to integrate Login512 securely into any ERP, POS, LMS, HR, or SaaS backend.

---

## 5 Built-In Industry Presets (1 Codebase)

Switch presets on first setup (`/setup`), anytime in `/admin`, or at launch via `DEFAULT_PRESET=<id>`:

| Preset ID | Use Case | Key Features |
|---|---|---|
| `classroom` | 🎓 **Classroom / Tutoring / Exam Room** | Projector Dynamic QR, Student ID & Section, stops buddy check-in & group-chat QR forwarding |
| `workplace` | 🏢 **Office / Retail / Clinic / Factory** | Tablet Clock-In / Clock-Out, optional Office Wi-Fi IP lock, UTF-8 Excel Payroll CSV export |
| `event` | 🎟️ **Event / Workshop / Fitness / VIP** | Live front-door attendee counter (SSE), stops pass sharing without storing guest photos |
| `checkpoint` | 🛡️ **Security Patrol / Housekeeping / Desk** | Fast 6s QR rotation, station rounds + site notes with ML-DSA-65 proof of time & identity |
| `dev-reference` | 💻 **Developer Reference (ERP / POS / SaaS)** | Auto-opens **Token Verify Inspector** showing `expected_nonce`, `mod`, `act`, `jti`, and ML-DSA-65 verification live |

---

## Pure-Web 3-Layer Anti-Spoof & Anti-Relay Architecture

Why this does **not** rely on browser GPS (which can be spoofed with Mock Location plugins):

1. **Layer 1 — Fast-Rotating Dynamic QR (5–8s rotation, ≤10s expiry):** Signed server-side with per-station HMAC-SHA256. Defeats Fake GPS and group-chat photo forwarding.
2. **Layer 2 — Optional On-Site Wi-Fi IP Allowlist (Anti-Video-Call Defense):** Admins can enable **Require On-Site Wi-Fi IP** per station (supports exact IPs, IPv4 CIDR like `192.168.1.0/24`, and a 1-click *"Use My Current IP"* button). Even if a friend streams the live Kiosk screen over a video call, any phone outside the authorized office/school Wi-Fi IP is hard-blocked at the server before scanning and again upon completion.
3. **Layer 3 — Login512 Biometric + Passkey Verification (`POST /v1/token/verify`):**
   - **Face Login:** Always bound to a server-issued single-use `expected_nonce` + ML-DSA-65 signature + single-use JTI replay protection (`0 bytes` of raw face images stored).
   - **Passkey Fallback:** Seamless Touch ID / Face ID / fingerprint fallback for harsh lighting or broken cameras, with strict server enforcement (`claims.mod === 'PASSKEY'`) so face tokens can never bypass `expected_nonce`.

---

## 2-Minute Quickstart

### Option A: Local Node.js (`>= 22.5`, zero native build tools required)

```bash
cp .env.example .env
# Add your Free Forever Login512 keys from https://login512.com/portal/index.html
npm install
npm start
```

Open `http://localhost:3512` — on first boot, a one-time **Genesis Setup Key** is printed in your terminal (no default `admin/1234` password!).

### Option B: Docker Compose

```bash
cp .env.example .env
docker compose up -d
docker compose logs -f   # read your one-time Genesis Setup Key on first boot
```

### Run Automated Tests (Offline)

```bash
npm test
```

### Build 5 Preset-Configured ZIPs (for GitHub Releases)

```bash
npm run build:zips
# Outputs 5 ZIPs into ./dist-zips/
```

---

## Copy-Paste Reference Files for Other Systems

If you are integrating Login512 into an existing app (ERP, POS, SaaS, LMS), start by reading just **3 short files**:
- `src/login512/client.js` — Official `@login512/server-sdk` wrapper enforcing `expected_nonce`, `step_up_required === false`, `act`, and `mod` separation.
- `src/login512/qr-guard.js` — Rotating HMAC Dynamic QR + CIDR/IP Wi-Fi Allowlist guard.
- `src/login512/genesis.js` — App-level First-Time Genesis Mode replacing insecure `admin/1234` bootstrap credentials.

---

## Security Notes for Production
- Keep `LOGIN512_SECRET_KEY` (`l512_sk_...`) strictly on the server (`.env`).
- Always serve behind **HTTPS** (mobile browsers require HTTPS for camera & Passkey access).
- Set `TRUST_PROXY=1` when deployed behind Nginx or Cloudflare so Wi-Fi IP Allowlist inspects the real client IP (`CF-Connecting-IP` / `X-Forwarded-For`).
- Keep `DEMO_MOCK_AUTH=false` in production (mock mode is strictly for local automated testing). The server refuses to start with mock mode on when `NODE_ENV=production` (the Docker image sets this) or when `PUBLIC_BASE_URL` is not localhost, and `/api/demo/mock-token` only answers requests from the same machine.
- Add your production domain to **Allowed Origins** in the [Login512 Developer Portal](https://login512.com/portal/index.html).

## License
Apache-2.0 — Free to use, customize, and deploy.
