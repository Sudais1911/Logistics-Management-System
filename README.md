# Logistics Chatbot — Public-Test Ready Prototype

## Included
- Role-based login.
- Owner login → Executive Owner Dashboard.
- Client login → Client Portal/chatbot.
- Signed session cookie and protected owner/client API routes.
- Responsive/mobile-friendly UI.
- Shipment tracking and client-facing updates.
- Owner inquiry management and contact shortcut.
- Global email batching: every 5 new shipment orders across ALL clients → one consolidated email to `thunders1911@gmail.com`.

## Local demo credentials
Owner: `owner` / `Owner@1234`
Client: `client` / `Client@1234`

Change these before public deployment using environment variables.

## Run locally
1. Copy `.env.example` to `.env`.
2. Put your Gmail App Password in `SMTP_APP_PASSWORD`.
3. Set strong `OWNER_PASSWORD`, `CLIENT_PASSWORD`, and `SESSION_SECRET`.
4. Run `python server.py`.
5. Open `http://127.0.0.1:5000`.

## Public test hosting on Render
1. Create a GitHub repository and upload the project files.
2. Create a Render **Web Service** connected to the repository.
3. Start Command: `python server.py` (Build Command can be left empty).
4. Add environment variables: `SESSION_SECRET`, `SECURE_COOKIE=1`, `OWNER_USERNAME`, `OWNER_PASSWORD`, `CLIENT_USERNAME`, `CLIENT_PASSWORD`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_APP_PASSWORD`, `SMTP_FROM`, `EMAIL_BATCH_SIZE=5`.
5. Deploy. Render supplies an HTTPS `onrender.com` URL.

The code binds to `0.0.0.0` and uses the `PORT` environment variable, as required by Render.

## Prototype limitation
The prototype stores data in JSON files. This is suitable for public testing but not production. For a real deployment, move data to a managed database and add password hashing/rotation, rate limiting, audit logging, backups, and stronger account management.

## Mobile
The client and owner pages use responsive layouts, mobile viewport settings and touch-friendly controls. The public HTTPS URL can be opened directly on Android/iPhone browsers.
