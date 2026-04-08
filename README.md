# jwt-refresh

<!-- Logo placeholder: add your project logo or banner here later. -->

> Refresh token rotation, race-condition protection, reuse detection, and session control for Node.js JWT flows.

`jwt-refresh` packages the part most teams keep rebuilding badly: secure refresh-token handling after access tokens expire. It gives you one library for token issuance, refresh rotation, replay detection, session revocation, access-token blacklisting, and middleware-friendly request handling.

## Why this exists

Most JWT setups solve signing and verification, but leave the refresh lifecycle to application code. That gap creates three recurring failures:

- refresh endpoints become bespoke security code
- concurrent refresh attempts log real users out
- stolen refresh tokens are reused without clear detection or response

This package focuses on those failures directly.

## Features

- Refresh-token rotation with per-session tracking
- Short grace window for simultaneous refresh bursts to avoid false theft detection
- Actual reuse detection for replayed rotated tokens
- Access-token blacklisting for immediate revocation
- Memory store for local development and tests
- Redis, Prisma, and Drizzle adapter surfaces for production storage
- Express-friendly middleware out of the box
- ESM, CJS, and generated TypeScript declarations

## Installation

```bash
npm install jwt-refresh jsonwebtoken
```

If you want Redis-backed storage, install your preferred Redis client separately and wire it into `RedisTokenStore`.

## Quick start

```ts
import express from 'express'
import { JwtManager, MemoryTokenStore } from 'jwt-refresh'

const app = express()
app.use(express.json())

const jwt = new JwtManager({
  access: {
    secret: process.env.JWT_SECRET!,
    ttl: '15m',
  },
  refresh: {
    secret: process.env.REFRESH_SECRET!,
    ttl: '7d',
    rotation: true,
    reuseDetection: true,
    absoluteExpiry: '90d',
  },
  cookie: {
    name: 'refreshToken',
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/auth',
  },
  refreshBuffer: 120,
  store: new MemoryTokenStore(),
})

app.post('/auth/login', async (_req, res) => {
  const { accessToken } = await jwt.issueTokens(
    res,
    {
      userId: 'user-1',
      email: 'user@example.com',
      roles: ['member'],
    },
    {
      deviceId: 'browser',
    },
  )

  res.json({ accessToken })
})

app.post('/auth/refresh', jwt.refreshHandler())
app.get('/api/me', jwt.authenticate(), (req, res) => res.json(req.user))
```

## What happens during refresh

```text
client sends refresh cookie
  -> refresh token signature is verified
  -> stored session is loaded by token id
  -> revoked rotation tokens inside the race window return 409 retry
  -> replayed rotated tokens trigger reuse detection and revoke all sessions
  -> a new access token and refresh token are issued
```

## Error model

`jwt-refresh` responds with JSON errors from its middleware and handlers:

```json
{
  "error": "Refresh token reuse detected",
  "code": "REFRESH_TOKEN_REUSED"
}
```

Typical status codes:

- `401` for missing, invalid, revoked, or replayed tokens
- `409` for a legitimate refresh race that should be retried with the updated cookie

## Session management

```ts
await jwt.revokeSession(userId, sessionId)
await jwt.revokeAllSessions(userId)
await jwt.blacklistToken(accessToken, { reason: 'password_changed' })

const sessions = await jwt.getSessions(userId)
```

Each session records:

- creation time
- last usage time
- device metadata
- parent token id for rotation lineage
- revoke status and revoke reason

## Security checklist

Recommended defaults for production:

- `refresh.rotation: true`
- `refresh.reuseDetection: true`
- `refresh.absoluteExpiry: '90d'`
- `cookie.httpOnly: true`
- `cookie.sameSite: 'strict'`
- `cookie.secure: true` on HTTPS deployments

See [docs/security-checklist.md](/root/jwt-refresh/docs/security-checklist.md) for the full checklist.

## API overview

```ts
class JwtManager<TPayload extends AccessTokenPayload = AccessTokenPayload> {
  issueTokens(res, payload, sessionMeta?)
  signAccessToken(payload)
  signRefreshToken(userId, sessionMeta?)
  verifyAccessToken(token)
  verifyRefreshToken(token)
  authenticate(options?)
  refreshHandler(options?)
  revokeCurrentSession(req, res)
  revokeSession(userId, sessionId)
  revokeAllSessions(userId)
  getSessions(userId, currentSessionId?)
  blacklistToken(token, options?)
}
```

## Package structure

```text
src/
  core/            manager, issuer, verifier, refresh coordinator
  middleware/      auth and refresh handlers
  mutex/           in-memory and redlock-compatible mutex adapters
  rotation/        rotation and reuse-detection logic
  session/         session and blacklist services
  stores/          memory, Redis, Prisma, and Drizzle adapters
  integrations/    express, fastify, nextjs, nestjs helpers
  testing/         test exports
tests/
  integration/     end-to-end request flow tests
  security/        race, replay, and expiry tests
```

## Examples

- [Express example](/root/jwt-refresh/examples/express-complete/server.ts)
- [Next.js App Router example](/root/jwt-refresh/examples/nextjs-app-router/route.ts)
- [NestJS example](/root/jwt-refresh/examples/nestjs/auth.controller.ts)

## Development

```bash
npm install
npm test
npm run build
```

## Contributing

See [CONTRIBUTING.md](/root/jwt-refresh/CONTRIBUTING.md).

## Security policy

See [SECURITY.md](/root/jwt-refresh/SECURITY.md).

## License

[MIT](/root/jwt-refresh/LICENSE)
