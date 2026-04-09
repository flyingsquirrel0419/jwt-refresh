# Comparison

## What `jwt-refresh` is

`jwt-refresh` is a refresh-lifecycle library. It assumes you still want JWTs, but you do not want to keep rebuilding the dangerous parts around them.

## Feature comparison

| Capability | jwt-refresh | jsonwebtoken | jose | passport-jwt | @nestjs/jwt |
|---|---:|---:|---:|---:|---:|
| JWT sign / verify | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh token rotation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Replay / reuse detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Legitimate refresh race handling | ✅ | ❌ | ❌ | ❌ | ❌ |
| Session revocation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Access-token blacklisting | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cookie-oriented refresh handler | ✅ | ❌ | ❌ | ❌ | ❌ |
| Memory store for tests | ✅ | ❌ | ❌ | ❌ | ❌ |
| Redis / ORM adapter surface | ✅ | ❌ | ❌ | ❌ | ❌ |

## Why not just use `jsonwebtoken`?

Because `jsonwebtoken` solves cryptographic JWT handling, not refresh-session state.

The missing parts are exactly where most bugs happen:

- deciding when a refresh token is still valid
- revoking a single session or all sessions
- telling a legitimate race apart from a replay attack
- rotating refresh chains without logging users out by accident

## Why this matters

Without a refresh lifecycle layer, teams usually end up with:

- bespoke `/auth/refresh` route logic
- duplicated cookie and session code
- replay handling that is either missing or too aggressive
- logout and password-reset behavior implemented in multiple places

`jwt-refresh` centralizes those rules in one package.
