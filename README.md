# Kavlod

Run: `node server.js` → http://localhost:8080 (Node 18+, no dependencies).
Docker: `docker build -t kavlod . && docker run -p 8080:8080 -v kavlod-data:/data kavlod`

Env: `PORT`, `DATA_DIR` (keep on a persistent disk), `CONTACT_EMAIL` (shown on /terms and /privacy), `FORCE_HTTPS=1` (behind a proxy that sets x-forwarded-proto).
Deploy on Render/Railway/Fly.io (HTTPS is required for mic, camera and screen sharing).
