# Add an industry (a 6th preset)

A preset is one JSON file in `presets/`. The app loads the 5 built-in presets first, then every other
`presets/<id>.json` sorted by id. No code change is needed.

## Steps

1. **Copy the closest built-in preset** and name the copy after your new id:

   ```bash
   cp presets/event.json presets/gym-class.json
   ```

   Pick the closest one: `classroom` (students), `workplace` (staff, clock-in/out), `event` (guests, live counter),
   `checkpoint` (patrol rounds with notes), `dev-reference` (developers).

2. **Edit the top of the file:**

   | Field | Rule |
   |---|---|
   | `id` | Must equal the file name without `.json`: 2–32 characters of `a-z`, `0-9` and `-` |
   | `icon` | One emoji, e.g. `"🏋️"` |
   | `accent` | A color like `"#22C55E"` |
   | `supportsClockOut` | `true` shows a check-out button (shifts); `false` is check-in only |
   | `allowNote` | `true` lets people add a note when checking in |
   | `showDevInspectorDefault` | `true` only for developer-facing presets |
   | `defaultQrRotateSec` | A whole number **from 5 to 8**. The fast-changing QR is what stops photos and video calls of the kiosk from working |

3. **Rewrite every text in both `th` and `en`.** All of these are required in each language:
   `name`, `shortName`, `tagline`, `defaultOrgName`, `defaultSiteName`, `memberLabel`, `memberCodeLabel`,
   `memberCodePlaceholder`, `groupLabel`, `groupPlaceholder`, `siteLabel`, `actionInLabel`, `actionOutLabel`,
   `notePlaceholder`, `kioskHeadline`, `kioskSub`, and `csvHeaders` (the column names of the CSV export).

4. **Check it:**

   ```bash
   npm run check:presets   # lists every preset as OK or FAIL with the exact problem
   npm test
   ```

   A preset with a problem is skipped (the others keep working) and the app logs
   `skipped presets/<id>.json: ...` at start.

5. **See it:** `npm start`, open `/setup` (first run) or `/admin` → the new industry is in the list.

6. **Optional: a ready-to-run ZIP.** `npm run build:zips` makes one ZIP per preset, yours included, in `dist-zips/`.

## What you cannot change in a preset

Security does not depend on the preset: token verification, nonces, the passkey check, CSRF and the no-photos rule
are in code and stay the same for every industry (see `AGENTS.md`, "Rules that must not be broken").
