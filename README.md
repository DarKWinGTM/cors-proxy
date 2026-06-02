# cors-proxy-worker
Cloudflare Worker — Transparent CORS Proxy
A hardened, transparent CORS proxy with **two deployment targets from the same codebase**:

| File | Target |
|---|---|
| `cors-proxy-worker.js` | Cloudflare Workers (edge, global) |
| `server.js` | Docker / local Node.js |

Security features: origin allowlist, target-host allowlist, cookie stripping, request/response header sanitization, no wildcard CORS headers.

---

## ⚡ One-click deploy to Cloudflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/amaryadav1/cors-proxy-worker)

> **Before sharing this button:** push this project to a **public** GitHub or GitLab repository and replace `YOUR_USERNAME/cors-proxy-worker` in the URL above with your actual repo path.

Clicking the button will:
1. Fork the repository into your GitHub/GitLab account
2. Let you rename the Worker and set any secrets
3. Build and deploy to `https://cors-proxy.<your-subdomain>.workers.dev` automatically

After deploying, open `cors-proxy-worker.js` in your forked repo and fill in the two allowlists:

```js
const ALLOWED_ORIGINS = new Set([
  "https://your-frontend.example.com",
]);

const ALLOWED_TARGET_HOSTS = new Set([
  "api.target-service.com",
]);
```

Commit the change — Workers Builds will redeploy automatically.

---

## Project structure

```
cors-proxy/
├── cors-proxy-worker.js   ← Cloudflare Worker (the proxy logic)
├── server.js              ← Node.js wrapper for Docker / local use
├── wrangler.jsonc         ← Wrangler config (primary, supports comments)
├── wrangler.toml          ← Wrangler config (TOML alternative — use one, not both)
├── .dev.vars.example      ← Secret declarations read by the Deploy button UI
├── .dev.vars              ← (gitignored) your actual local secret values
├── package.json           ← scripts + cloudflare.bindings descriptions
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```

---

## Local deployment — Docker

```bash
# Build and start (port 8080)
docker compose up --build

# Background
docker compose up --build -d
```

The proxy will be available at **http://localhost:8080**.

### Change the port

```bash
HOST_PORT=3000 docker compose up --build
```

Or create a `.env` file:

```env
HOST_PORT=3000
PORT=3000
```

---

## Local deployment — Node.js (no Docker)

```bash
node server.js
# or with auto-restart on file changes:
npm run dev:node
```

---

## Usage

Append your target URL as the `?url=` query parameter:

```
http://localhost:8080/?url=https://api.example.com/endpoint
```

### curl examples

```bash
# GET
curl "http://localhost:8080/?url=https://api.example.com/data"

# POST with JSON body
curl -X POST "http://localhost:8080/?url=https://api.example.com/data" \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'

# With Authorization header
curl "http://localhost:8080/?url=https://api.example.com/data" \
  -H "Authorization: Bearer <token>"

# PUT / PATCH / DELETE
curl -X DELETE "http://localhost:8080/?url=https://api.example.com/items/1"
```

### Browser / fetch

```js
const res = await fetch(
  "https://cors-proxy.<subdomain>.workers.dev/?url=https://api.example.com/data",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer TOKEN",
    },
    body: JSON.stringify({ key: "value" }),
  }
);
const data = await res.json();
```

---

## Manual deploy to Cloudflare Workers

Use this if you want to deploy from the CLI without the button.

### 1. Install Wrangler

```bash
npm install          # installs wrangler from devDependencies
# or globally:
npm install -g wrangler
```

### 2. Authenticate

```bash
npx wrangler login
```

### 3. Run locally with Wrangler

```bash
npm run dev
# → http://localhost:8787
```

Copy `.dev.vars.example` to `.dev.vars` and fill in any secret values for local testing.

### 4. Deploy

```bash
npm run deploy
# → https://cors-proxy.<your-subdomain>.workers.dev
```

### 5. Set production secrets

```bash
npx wrangler secret put PROXY_AUTH_TOKEN
# Prompts for value — stored encrypted, never in config files
```

### Custom domain (optional)

Uncomment the `routes` block in `wrangler.jsonc` and set `"workers_dev": false`:

```jsonc
"workers_dev": false,
"routes": [
  {
    "pattern": "proxy.example.com/*",
    "custom_domain": true
  }
]
```

Then redeploy: `npm run deploy`.

---

## Behaviour reference

| Scenario | Response |
|---|---|
| `OPTIONS` preflight from allowed origin | `204` + precise CORS headers |
| `OPTIONS` from blocked origin | `403` (no CORS headers — browser can't read body) |
| Missing `?url=` | `400` JSON error |
| Non-https target | `400` JSON error |
| Malformed URL | `400` JSON error |
| Target host not in allowlist | `403` JSON error |
| Private/internal IP target | `403` JSON error |
| Upstream unreachable | `502` JSON error |
| Unsupported method | `405` |
| All other requests | Proxied response + CORS headers injected, cookies stripped |
