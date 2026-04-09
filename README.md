<!-- Logo placeholder: add ./logo.png and replace this comment with a centered image block later. -->

<h1 align="center">jwt-refresh</h1>

<p align="center">
  <strong>The JWT refresh lifecycle toolkit that Node.js apps actually need.</strong><br>
  <em>Refresh rotation, reuse detection, race-condition protection, and session control in one package.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/npm-unpublished-CB3837?logo=npm&logoColor=white" alt="npm unpublished">
  <img src="https://img.shields.io/badge/downloads-unpublished-blue" alt="downloads unavailable">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="license"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-first-3178C6?logo=typescript&logoColor=white" alt="TypeScript"></a>
  <img src="https://img.shields.io/badge/Node.js-%E2%89%A5_18-339933?logo=nodedotjs&logoColor=white" alt="Node.js >= 18">
  <img src="https://img.shields.io/badge/tests-64_passing-brightgreen" alt="tests">
  <img src="https://img.shields.io/badge/coverage-99.05%25-brightgreen" alt="coverage">
  <a href="https://github.com/flyingsquirrel0419/jwt-refresh/actions/workflows/ci.yml"><img src="https://github.com/flyingsquirrel0419/jwt-refresh/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a>&nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="#-features">Features</a>&nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="./docs/api.md">API Reference</a>&nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="./docs/security-checklist.md">Security</a>&nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="#-integrations">Integrations</a>&nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="./docs/comparison.md">Comparison</a>&nbsp;&nbsp;|&nbsp;&nbsp;
  <a href="./docs/architecture.md">Architecture</a>
</p>

---

## The Problem

Every hand-rolled JWT stack eventually hits the same refresh wall:

```text
jsonwebtoken only         --> signs and verifies tokens, but leaves refresh flows to app code
custom refresh endpoint   --> works until rotation, replay detection, and logout rules pile up
multiple browser tabs     --> all try to refresh at once, then users get logged out by accident
stolen refresh token      --> gets replayed without a clear security response
```

The failure mode is almost always the same: a team solves "issue access tokens" and underestimates "manage the refresh lifecycle safely".

## The Solution

**jwt-refresh** packages the refresh lifecycle as a first-class system:

```text
client request
  -> access token verification
  -> refresh cookie extraction
  -> refresh token verification
  -> session lookup
  -> race-condition guard
  -> rotation or replay decision
  -> blacklist / revoke / event emission
  -> new access token + refresh token
```

Instead of sprinkling refresh logic across routes, services, and middleware, you get one manager that owns:

- refresh token rotation
- reuse detection
- legitimate race handling
- access-token blacklisting
- session revocation
- framework-friendly handlers

---

## Quick Start

### Install

`jwt-refresh` is not published under a safe npm name yet. For now, install from GitHub:

```bash
npm install github:flyingsquirrel0419/jwt-refresh jsonwebtoken
```

### Minimal example

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
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
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

### What refresh handling looks like

```text
POST /auth/refresh
  -> reads refresh cookie
  -> verifies JWT signature and claims
  -> checks stored session state
  -> returns 409 retry for a legitimate in-flight race
  -> revokes all sessions on replayed rotated tokens
  -> rotates refresh token and returns a fresh access token
```

---

## Features

### Token lifecycle

| Feature | What it does |
|---|---|
| **Refresh token rotation** | Issues a new refresh token on successful refresh and revokes the previous session |
| **Absolute expiry** | Stops endless refresh chains and forces re-authentication after a fixed window |
| **Access-token blacklisting** | Rejects still-valid access tokens immediately after sensitive events |
| **Cookie-aware refresh flow** | Reads and writes refresh cookies without route boilerplate |

### Security

| Feature | What it does |
|---|---|
| **Reuse detection** | Detects replayed rotated refresh tokens and revokes all active sessions for the user |
| **Race-condition protection** | Distinguishes a real replay from a legitimate multi-request refresh burst |
| **Session-level revocation** | Revokes one device, the current device, or all devices |
| **Security events** | Emits `token:reuse-detected`, `token:revoked`, and refresh-related events |

### Developer experience

| Feature | What it does |
|---|---|
| **Typed payloads** | `JwtManager<TPayload>` preserves your access-token payload type |
| **Framework helpers** | Express-first handlers plus Fastify, Next.js, and NestJS adapters |
| **Multiple store adapters** | Memory store for tests, plus Redis, Prisma, and Drizzle adapter surfaces |
| **ESM + CJS** | Ships generated declaration files and dual module output |

### Quality

| Feature | What it does |
|---|---|
| **64 passing tests** | Integration, security, and deep unit coverage across core and adapter branches |
| **99.05% line coverage** | High confidence in the refresh, security, and adapter control flow |
| **GitHub Actions CI** | Lint, test, coverage, and build on push and pull request |

---

## Integrations

`jwt-refresh` is designed to sit inside the web stack you already use:

| Framework | Integration |
|---|---|
| **Express** | `jwt.authenticate()` and `jwt.refreshHandler()` as route-ready handlers |
| **Fastify** | `createFastifyHandler(jwt, 'authenticate' | 'refresh')` bridge |
| **Next.js App Router** | `verifyNextRequest()` and `createNextRefreshHandler()` helpers |
| **NestJS** | `createNestGuard()` and `getJwtUser()` for guard-style integration |

<details>
<summary><b>Express example</b></summary>

```ts
import express from 'express'
import { JwtManager, MemoryTokenStore } from 'jwt-refresh'

const app = express()
const jwt = new JwtManager({
  access: { secret: process.env.JWT_SECRET!, ttl: '15m' },
  refresh: { secret: process.env.REFRESH_SECRET!, ttl: '7d', rotation: true, reuseDetection: true },
  store: new MemoryTokenStore(),
})

app.post('/auth/refresh', jwt.refreshHandler())
app.get('/api/me', jwt.authenticate(), (req, res) => res.json(req.user))
```

</details>

<details>
<summary><b>Next.js App Router example</b></summary>

```ts
import { createNextRefreshHandler } from 'jwt-refresh/integrations/nextjs'

export const POST = createNextRefreshHandler(jwt)
```

</details>

<details>
<summary><b>NestJS example</b></summary>

```ts
import { createNestGuard } from 'jwt-refresh/integrations/nestjs'

const JwtAuthGuard = createNestGuard(jwt)
```

</details>

---

## API

The public API is intentionally compact:

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

See [API Reference](./docs/api.md) for the full option and method surface.

---

## Security Defaults

Recommended production defaults:

- `refresh.rotation: true`
- `refresh.reuseDetection: true`
- `refresh.absoluteExpiry: '90d'`
- `cookie.httpOnly: true`
- `cookie.sameSite: 'strict'`
- `cookie.secure: true` in production

See the full [security checklist](./docs/security-checklist.md).

---

## Comparison

`jwt-refresh` is not trying to replace low-level JWT libraries. It sits above them and solves the lifecycle problems they intentionally leave to application code.

| Package | Signs JWTs | Rotation | Reuse detection | Race handling | Session revoke | Access blacklist |
|---|---:|---:|---:|---:|---:|---:|
| `jwt-refresh` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `jsonwebtoken` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `jose` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `passport-jwt` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `@nestjs/jwt` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

More detail: [Comparison](./docs/comparison.md)

---

## Development

```bash
npm install
npm run lint
npm test
npm run coverage
npm run build
```

## Repository docs

- [API Reference](./docs/api.md)
- [Architecture](./docs/architecture.md)
- [Changelog](./CHANGELOG.md)
- [Security Checklist](./docs/security-checklist.md)
- [Comparison](./docs/comparison.md)
- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)

## License

[MIT](./LICENSE)
