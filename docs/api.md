# API Reference

## `JwtManager`

```ts
class JwtManager<TPayload extends AccessTokenPayload = AccessTokenPayload> {
  constructor(options: JwtManagerOptions<TPayload>)

  issueTokens(res, payload, sessionMeta?)
  signAccessToken(payload)
  signRefreshToken(userId, sessionMeta?)
  verifyAccessToken(token)
  verifyRefreshToken(token)
  authenticate(options?)
  refreshHandler(options?)
  refreshToken(refreshToken, req)
  revokeCurrentSession(req, res)
  revokeSession(userId, sessionId)
  revokeAllSessions(userId)
  getSessions(userId, currentSessionId?)
  blacklistToken(token, options?)
  isBlacklisted(jti)
  getCookieOptions()
  getRefreshBuffer()
  getRefreshCookie(req)
}
```

## `JwtManagerOptions`

```ts
interface JwtManagerOptions<TPayload extends AccessTokenPayload> {
  access: JwtTokenOptions
  refresh: RefreshTokenOptions
  store: TokenStore<TPayload>
  mutex?: 'memory' | MutexAdapter
  cookie?: CookieOptions
  refreshBuffer?: number
  onStoreError?: 'throw' | 'warn'
  extractContext?: (req: RequestLike) => Record<string, unknown>
}
```

### `access`

- `secret`: signing secret for access tokens
- `ttl`: access-token lifetime, such as `'15m'`
- `algorithm`: optional signing algorithm, default `HS256`
- `issuer`: optional `iss`
- `audience`: optional `aud`
- `legacySecrets`: old verification secrets during secret rotation

### `refresh`

- `secret`: signing secret for refresh tokens
- `ttl`: refresh-token lifetime, such as `'7d'`
- `rotation`: whether refresh rotates to a new session
- `reuseDetection`: whether replayed rotated tokens revoke all sessions
- `absoluteExpiry`: maximum age of the refresh chain
- `algorithm`, `issuer`, `audience`, `legacySecrets`: same idea as access tokens

### `cookie`

- `name`
- `httpOnly`
- `secure`
- `sameSite`
- `domain`
- `path`
- `maxAge`

## Session methods

### `issueTokens(res, payload, sessionMeta?)`

Issues an access token and a refresh token, stores the session, and writes the refresh cookie.

Returns:

```ts
{
  accessToken: string
  refreshToken: string
  sessionId: string
}
```

### `revokeCurrentSession(req, res)`

Revokes the current session if `req.auth` is present and clears the refresh cookie.

### `revokeSession(userId, sessionId)`

Revokes one session by session id.

### `revokeAllSessions(userId)`

Revokes all sessions for the user.

### `getSessions(userId, currentSessionId?)`

Lists sessions with `isCurrent` derived from `currentSessionId`.

## Middleware

### `authenticate(options?)`

Validates the bearer access token, rejects blacklisted tokens, and attaches:

```ts
req.user
req.auth
```

### `refreshHandler(options?)`

Reads the refresh cookie, runs refresh orchestration, writes the new cookie, and returns:

```json
{
  "accessToken": "...",
  "sessionId": "..."
}
```

On a legitimate refresh race, the handler returns `409` with:

```json
{
  "error": "Refresh already in progress. Retry with the updated cookie."
}
```

and sets `X-Refresh-Retry: true`.

## Events

`JwtManager` extends `EventEmitter`.

Supported events:

- `token:issued`
- `token:refreshed`
- `token:revoked`
- `token:reuse-detected`
- `store:error`

## Stores

Included adapters:

- `MemoryTokenStore`
- `RedisTokenStore`
- `PrismaTokenStore`
- `DrizzleTokenStore`

The memory store is production-safe only for single-process development or tests. For multi-instance deployments, use a shared store and a distributed mutex strategy.
