import { JwtRefreshError } from '../errors'
import type { AccessTokenPayload, RefreshHandlerOptions, RequestHandler } from '../types'
import { jsonResponse, setCookie } from '../utils'
import type { JwtManager } from '../core/JwtManager'

export function createRefreshHandler<TPayload extends AccessTokenPayload>(
  jwt: JwtManager<TPayload>,
  options: RefreshHandlerOptions,
): RequestHandler {
  return async (req, res, next) => {
    try {
      const refreshToken = jwt.getRefreshCookie(req)
      if (!refreshToken) {
        throw new JwtRefreshError('Missing refresh token', 401, 'REFRESH_TOKEN_MISSING')
      }

      const result = await jwt.refreshToken(refreshToken, req)
      if (result.type === 'retry') {
        res.setHeader('X-Refresh-Retry', 'true')
        return jsonResponse(res, 409, { error: 'Refresh already in progress. Retry with the updated cookie.' })
      }

      const cookieOptions = jwt.getCookieOptions()
      setCookie(res, options.cookieName ?? cookieOptions.name, result.refreshToken, cookieOptions)
      return jsonResponse(res, 200, {
        accessToken: result.accessToken,
        sessionId: result.sessionId,
      })
    } catch (error) {
      const failure =
        error instanceof JwtRefreshError ? error : new JwtRefreshError('Refresh failed', 401, 'REFRESH_FAILED')
      return jsonResponse(res, failure.statusCode, { error: failure.message, code: failure.code })
    }
  }
}
