import type { VerifyOptions } from 'jsonwebtoken'

import type { AccessTokenPayload, JwtManagerOptions, VerifiedAccessPayload, VerifiedRefreshPayload } from '../types'
import { JwtRefreshError } from '../errors'
import { normalizeRefreshPayload, verifyJwt } from '../utils'

export class TokenVerifier<TPayload extends AccessTokenPayload> {
  constructor(private readonly options: JwtManagerOptions<TPayload>) {}

  verifyAccessToken(token: string): VerifiedAccessPayload<TPayload> {
    try {
      return verifyJwt<VerifiedAccessPayload<TPayload>>(
        token,
        [this.options.access.secret, ...(this.options.access.legacySecrets ?? [])],
        this.buildVerifyOptions(this.options.access),
      )
    } catch {
      throw new JwtRefreshError('Invalid or expired access token', 401, 'ACCESS_TOKEN_INVALID')
    }
  }

  verifyRefreshToken(token: string): VerifiedRefreshPayload {
    try {
      const payload = verifyJwt(
        token,
        [this.options.refresh.secret, ...(this.options.refresh.legacySecrets ?? [])],
        this.buildVerifyOptions(this.options.refresh),
      )

      return normalizeRefreshPayload(payload)
    } catch {
      throw new JwtRefreshError('Invalid or expired refresh token', 401, 'REFRESH_TOKEN_INVALID')
    }
  }

  private buildVerifyOptions(options: JwtManagerOptions<TPayload>['access']): VerifyOptions {
    const audience = Array.isArray(options.audience)
      ? ([...options.audience] as [string, ...string[]])
      : options.audience

    return {
      algorithms: [options.algorithm ?? 'HS256'],
      issuer: options.issuer,
      audience,
    }
  }
}
