# Trade Advice Backend

Node.js/Express API with MongoDB, JWT auth, wallet tracking, and Socket.IO streaming. This repo is now production-ready for Render and consumable from a Flutter client (mobile or web).

## Prerequisites

- Node.js 20+
- MongoDB instance (local or Atlas)
- Twilio credentials (optional; used for OTP SMS)

## Environment Variables

Copy .env.example to .env and fill in the values:

| Key | Description |
| --- | --- |
| PORT, HOST | Listening interface/port. Render sets PORT automatically. |
| CORS_ALLOWED_ORIGINS | Comma-separated list of allowed HTTP origins. Leave empty for dev/mobile clients. |
| SOCKET_ALLOWED_ORIGINS | Optional override for Socket.IO origins. |
| RATE_LIMIT_WINDOW_MS / RATE_LIMIT_MAX | Configure HTTP rate limiting. |
| MONGODB_URI | MongoDB connection string. |
| JWT_SECRET | Secret used to sign access tokens. |
| OTP_EXP_MIN | Minutes before OTP expires. |
| ADMIN_SIGNUP_TOKEN | Bootstrap token for admin registration endpoint. |
| MONGOOSE_DEBUG | Set to 1 to enable query logging. |
| TWILIO_* | Twilio credentials to send real SMS. Leave blank to log codes locally. |

## Local Development

`ash
npm install
npm run dev
`

The API exposes:
- GET / basic status document (useful for Render health monitoring).
- GET /api/health health check.
- POST /api/auth/request-otp, POST /api/auth/verify-otp phone login flow.
- POST /api/auth/admin/* endpoints for admin bootstrap/login.
- GET /api/advice/latest, POST /api/advice, POST /api/advice/:id/unlock for advice lifecycle.
- GET /api/wallet wallet summary.
- Socket.IO namespace at the same origin emitting market:tick demo events.

## Deploying to Render

1. Commit these changes and push to GitHub.
2. Update ender.yaml with your desired service name, region, and origins.
3. In Render, choose **New + → Blueprint > From repo** and select this repository.
4. When prompted, set the environment variables that are flagged with sync: false (e.g. MONGODB_URI, Twilio secrets).
5. Render will run 
pm install during build and 
pm run start to boot the service. Health checks target /api/health.
6. Add your Flutter production origin to CORS_ALLOWED_ORIGINS (and SOCKET_ALLOWED_ORIGINS if different). For mobile-only clients you can leave them blank.

## Connecting From Flutter

Use the deployed Render URL as your API base (e.g. https://trade-advice-api.onrender.com).

- REST: Send standard JSON requests with the Authorization: Bearer <token> header once authenticated.
- Socket.IO: Connect with the same base URL: io('https://trade-advice-api.onrender.com', { transports: ['websocket'] });. The backend already mirrors HTTP CORS rules for websockets.
- Remember to handle 401/403 responses and refresh OTP logins.

## Operational Notes

- The server now trusts Render's reverse proxy (pp.set('trust proxy', 1)) so rate limiting and IP logging continue to work.
- Graceful shutdown hooks close HTTP and MongoDB connections when Render cycles instances.
- Logs are optimized for production (combined) when NODE_ENV=production.
