# Security Checklist

## Required

- Use different secrets for access and refresh tokens.
- Keep `refresh.rotation` enabled.
- Keep `refresh.reuseDetection` enabled.
- Set `cookie.httpOnly` to `true`.
- Set `cookie.sameSite` to `'strict'` or `'lax'`.
- Set `cookie.secure` to `true` in production.

## Strongly recommended

- Set `refresh.absoluteExpiry` to a finite window such as `90d`.
- Keep access-token TTL short.
- Use a distributed mutex in multi-instance deployments.
- Wire `token:reuse-detected` into alerting.
- Blacklist access tokens on password resets and forced sign-outs.

## Secret generation

Generate at least 32 random bytes per secret:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## Incident response

If you suspect token theft:

1. rotate signing secrets if compromise is possible
2. revoke all active sessions for the affected user
3. force re-authentication
4. investigate session metadata such as user agent and IP
