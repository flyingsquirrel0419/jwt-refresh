import { JwtRefreshError } from '../errors'
import type { AccessTokenPayload, AuthenticateOptions, RequestHandler } from '../types'
import { extractBearerToken, jsonResponse, normalizeAccessPayload } from '../utils'
import type { JwtManager } from '../core/JwtManager'

export function createAuthenticateHandler<TPayload extends AccessTokenPayload>(
  jwt: JwtManager<TPayload>,
  options: AuthenticateOptions,
): RequestHandler {
  return async (req, res, next) => {
    try {
      const token = extractBearerToken(req)
      if (!token) {
        throw new JwtRefreshError('Missing access token', 401, 'ACCESS_TOKEN_MISSING')
      }

      const payload = jwt.getTokenVerifier().verifyAccessToken(token)
      if (await jwt.isBlacklisted(payload.jti)) {
        throw new JwtRefreshError('Token has been revoked', 401, 'ACCESS_TOKEN_REVOKED')
      }

      req.user = normalizeAccessPayload(payload)
      req.auth = {
        userId: payload.userId,
        tokenId: payload.jti,
        sessionId: payload.sid,
      }

      if (options.rotateOnResponse && payload.exp) {
        const secondsLeft = payload.exp - Math.floor(Date.now() / 1000)
        if (secondsLeft <= jwt.getRefreshBuffer()) {
          const refreshed = jwt.signAccessToken(req.user as TPayload)
          res.setHeader('Authorization-Refreshed', `Bearer ${refreshed}`)
        }
      }

      return next?.()
    } catch (error) {
      const failure = error instanceof JwtRefreshError ? error : new JwtRefreshError('Unauthorized', 401, 'UNAUTHORIZED')
      return jsonResponse(res, failure.statusCode, { error: failure.message, code: failure.code })
    }
  }
}
