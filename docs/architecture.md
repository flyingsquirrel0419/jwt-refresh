# Architecture

`jwt-refresh` is organized around the refresh lifecycle rather than around plain JWT signing.

## Main components

- `JwtManager`: public API and orchestration layer
- `TokenIssuer`: signs access and refresh tokens
- `TokenVerifier`: verifies token signatures and claims
- `RefreshCoordinator`: handles refresh requests, mutexing, replay decisions, and expiry checks
- `RotationEngine`: creates the next refresh session and revokes the previous one
- `ReuseDetector`: revokes all sessions when a rotated token is replayed outside the race window
- `SessionManager`: lists and revokes sessions
- `BlacklistManager`: blacklists access tokens until expiration
- `TokenStore`: backing store contract for session state and blacklists

## Refresh flow

```text
verify refresh jwt
  -> load session by token id
  -> compare token hash
  -> check absolute expiry
  -> handle revoked rotation token as retry or replay
  -> create next session
  -> revoke previous session
  -> return new tokens
```
