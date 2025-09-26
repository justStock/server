# Trade Advice Backend

Node.js/Express API with MongoDB, JWT auth, wallet tracking, and Socket.IO streaming. The backend now exposes production-safe defaults for Render and is ready for a Flutter client (mobile or web).

## Prerequisites

- Node.js 20+
- MongoDB instance (local or Atlas)
- Twilio credentials (optional; used for OTP SMS)

## Environment Variables

Copy `.env.example` to `.env` and fill in the values:

| Key | Description |
| --- | --- |
| PORT, HOST | Listening interface/port. Render injects PORT automatically. |
| CORS_ALLOWED_ORIGINS | Comma-separated HTTP origins. Leave empty for dev/mobile clients. |
| SOCKET_ALLOWED_ORIGINS | Optional override for Socket.IO origins. |
| RATE_LIMIT_WINDOW_MS / RATE_LIMIT_MAX | HTTP rate limiting configuration. |
| MONGODB_URI | MongoDB connection string. |
| JWT_SECRET | Secret used to sign access tokens. |
| OTP_EXP_MIN | Minutes before OTP expires. |
| ADMIN_OTP_EXP_MIN | Override admin OTP expiry minutes (defaults to `OTP_EXP_MIN`). |
| ADMIN_OTP_ALLOWED_PHONES | Optional comma-separated allowlist of admin phones (E.164, e.g. `+911234567890`). |
| ADMIN_SIGNUP_TOKEN | Bootstrap token for admin registration endpoint. |
| MONGOOSE_DEBUG | Set to `1` to enable query logging. |
| TWILIO_* | Twilio credentials for real SMS sending. Leave blank to log codes locally. |
| CLOUDINARY_URL | Alternative single var: `cloudinary://<api_key>:<api_secret>@<cloud_name>` |
| CLOUDINARY_CLOUD_NAME | Cloudinary cloud name for uploads. (Used if `CLOUDINARY_URL` not set) |
| CLOUDINARY_API_KEY | Cloudinary API key. (Used if `CLOUDINARY_URL` not set) |
| CLOUDINARY_API_SECRET | Cloudinary API secret (server-side signing). (Used if `CLOUDINARY_URL` not set) |
| CLOUDINARY_UPLOAD_FOLDER | Optional default folder for uploads (e.g. `admin-uploads`). |

## Local Development

```bash
npm install
npm run dev
```

Key endpoints:
- `GET /` simple status payload for uptime checks.
- `GET /api/health` Render health check target.
- `POST /api/auth/request-otp` and `POST /api/auth/verify-otp` phone login flow.
- `POST /api/auth/admin/request-otp` and `POST /api/auth/admin/verify-otp` phone OTP auth for admins.
- `POST /api/auth/admin/login` email/password login for legacy admins.
- `GET /api/advice/latest`, `POST /api/advice`, `POST /api/advice/:id/unlock` advice lifecycle.
- `GET /api/wallet` wallet summary.
- Socket.IO emits `market:tick` demo events on the same origin.

### Images (Admin uploads to Cloudinary, users list images)

- `POST /api/images/signature` (admin): returns Cloudinary upload signature/params for direct client uploads.
  - Body: `{ folder?: string, tags?: string[] }`
  - Response: `{ cloudName, apiKey, timestamp, signature, folder, tags, uploadUrl }`
- Upload each selected file directly from the client to `uploadUrl` with multipart form fields:
  - `file` (binary or data URL), `api_key`, `timestamp`, `signature`, and optional `folder`, `tags`.
- `POST /api/images/batch` (admin): persist uploaded items to DB after successful Cloudinary upload.
  - Body: `{ items: Array<CloudinaryUploadResult> }` where each item includes `public_id`, `secure_url`, etc.
- `GET /api/images` (public): returns recent images for the user app: `{ items: [{ id, url, width, height, format, folder, createdAt }] }`.

## Deploying to Render

1. Commit these changes and push to your repository.
2. Review `render.yaml` and adjust the service name, region, and CORS origins to match your deployment.
3. In Render, pick **New > Blueprint > From repo**, select this repo, and let Render read `render.yaml`.
4. Supply values for variables marked with `sync: false` (e.g. `MONGODB_URI`, Twilio secrets) and tweak auto-generated secrets if needed.
5. Render runs `npm install` during build and `npm run start` at runtime. Health checks hit `/api/health`.
6. Add your Flutter production origin(s) to `CORS_ALLOWED_ORIGINS` (and `SOCKET_ALLOWED_ORIGINS` if websockets are hosted elsewhere). Leave them blank for native mobile apps during development.

## Connecting From Flutter

- REST: Point your HTTP client at the Render base URL (e.g. `https://trade-advice-api.onrender.com`) and attach `Authorization: Bearer <token>` once authenticated.
- Socket.IO: `io('https://trade-advice-api.onrender.com', { transports: ['websocket'] })` uses the same CORS whitelist as HTTP.
- Handle 401/403 responses by restarting the OTP flow.

## Operational Notes

- `app.set('trust proxy', 1)` keeps rate limiting/IP logging accurate behind Render's proxy.
- Graceful shutdown closes the HTTP listener and MongoDB connection on `SIGTERM/SIGINT` so instances recycle cleanly.
- When `NODE_ENV=production`, logs switch to the `combined` format for better observability.
