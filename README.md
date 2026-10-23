# Elite Trading V4 — Node.js + PostgreSQL

## What is implemented
- Nine updated user-facing HTML pages + `admin.html`; CSS and page-specific JavaScript are embedded in each HTML page. Only `public/elite-core.js` is shared.
- Backend signup, login, logout and account lookup (bcrypt password hashes, HttpOnly cookies, JWT with 12-hour expiry).
- PostgreSQL-backed user records; admin can list users and recorded balances.
- Admin-only BTC address configuration. Users see the current address and generated QR after the admin saves it.
- Bitcoin-only funding; minimum $20; USD/BTC estimate with **illustrative** 1% charge.
- Two BTC chart views and a 14-asset market watchlist. Live public feeds can be delayed or rate limited.
- Market-feed status and unavailable states instead of fabricated quotes.

## Critical limitations
This is **not a production-ready custodial investment service**. It does not accept or confirm deposits, execute trades, custody assets, verify identities, send reset emails, enforce 2FA, reconcile blockchain transactions or credit balances. New users start with $0. Admin sees recorded balance (currently $0 because no ledger is integrated). Never accept customer funds until secure deposit reconciliation, compliance, wallet infrastructure, and accounting are implemented and independently reviewed. The 1% fee is an example; determine your legitimate pricing and disclose it before enabling deposits. A shared platform deposit address does not by itself link incoming transactions to individual users. The QR code uses a third-party image service; for privacy/security, replace with a vetted local QR generator before production.

## Deploy to Railway
1. Upload this **project root**, not just the public directory, to a GitHub repository.
2. Railway: **New Project → Deploy from GitHub repo**.
3. Add a Railway **PostgreSQL** service.
4. Set `DATABASE_URL=${{Postgres.DATABASE_URL}}` on your app service, `JWT_SECRET` (32+ random chars), `ADMIN_EMAIL`, `ADMIN_PASSWORD` (12+ chars), and `NODE_ENV=production`. Do NOT use `admin123` on the internet. Never commit your actual `.env` file.
5. Deploy. Railway detects Node.js and uses `npm start`. The service serves frontend and API from the same domain. Under Networking, generate a domain.
6. Sign in using the admin credentials defined in Railway Variables, then visit `/admin.html`. Standard users sign up normally and cannot use admin endpoints.
7. Save **only a Bitcoin mainnet receiving address owned by your company**. Verify the address on hardware and audit deposit custody before enabling real payments.

## Local run
Provide `DATABASE_URL`, `JWT_SECRET` and optionally `ADMIN_EMAIL`/`ADMIN_PASSWORD` in your shell environment, then run `npm install && npm start`. Open `http://localhost:3000`. The application does not automatically load `.env` files.

## Security work before a real launch
Email verification and reset, database-backed session revocation, CSRF protection, hardened CSP, multi-factor authentication, immutable double-entry ledger, user-specific deposit assignment, monitored on-chain confirmations, monitoring/backups, regulatory review, KYC/AML, admin authorization review, wallet security procedures, and external security testing.


## Shared frontend configuration (V4 centralized update)

All 10 HTML pages load `/elite-core.js`, and each page retains its own embedded CSS and page-specific JavaScript. Backend API requests go through `Elite.apiFetch()` rather than each page having to know the API base URL.

- For **one Railway deployment** that serves pages and API, keep `API_BASE_URL: ''`. No URL edits are needed.
- If the frontend is deployed separately, put its backend HTTPS origin in `API_BASE_URL`. The backend must also explicitly authorize that origin with credentials-enabled CORS and appropriate cookie settings; changing this file alone does not enable cross-site authentication.
- `Elite.apiJSON`, `Elite.post`, `Elite.put` are shared request helpers available to newly built pages.
- Editing `elite-core.js` updates shared public settings and the API base for every page. It cannot change page-specific HTML or secret/server-side settings.
- Do not place admin credentials, secret keys, deposit wallet private keys, or investment balance values in this public file.

Backend endpoints remain under `/api/` and admin functionality is authorized on the server. BTC addresses are managed through the admin and database; user funding pages read them from `/api/funding/config`.


## External PostgreSQL database / separate Railway project
A PostgreSQL database can be in a completely separate Railway project or an external PostgreSQL provider. In the Railway **application service** set `DATABASE_URL` to the connection string for that database. Use the database's externally reachable TCP/SSL hostname when projects are isolated; a private hostname from another Railway project may not be reachable. Use `PGSSL=true` only when required by your database provider, and verify the provider's TLS requirements before live use. Allow access through any database IP/network restrictions. The app must be able to reach the database and the database user must have permissions to create/query its required tables.

The HTML frontend should connect to the **API**, not directly to PostgreSQL. When frontend and Node.js server use one Railway domain, `API_BASE_URL: ''` is correct. For separate frontend hosting, edit only `public/elite-core.js` to use your backend HTTPS domain, and configure HTTPS, CORS and credential cookie security on the server; do not expose database credentials to browser code.


## Final layout — one shared JS file
Every HTML file contains its **own internal CSS and page-specific JavaScript**. The landing page `index.html` is located at the project root; the other pages are in `public/`. The **only** JavaScript file directly inside `public/` is `elite-core.js`, shared by all 10 HTML pages. Edit `API_BASE_URL` there to change the API origin for all pages. Keep `server.js` outside `public/` and configure `DATABASE_URL` on Railway for the separate database.


## V7 — Root homepage layout
`index.html` is now at the repository root, outside `public/`. The Express server responds to `/` with that root file and redirects `/index.html` to `/`. All other HTML pages and the only shared browser JS file (`public/elite-core.js`) remain in `public/`. The root homepage loads it via `/elite-core.js`; all CSS and page-specific JS stay embedded in their respective HTML files.

**Important:** When deploying with the included Express server on Railway, deploy the whole repository root (not just `public/`). A standalone static-site host would require a separate setup because its publish directory and routing rules differ.
