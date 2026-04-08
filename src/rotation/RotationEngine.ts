import { randomUUID } from 'node:crypto'

import { JwtRefreshError } from '../errors'
import type { AccessTokenPayload, JwtManagerOptions, RefreshSuccessResult, RefreshTokenSession, RequestLike, SessionMeta } from '../types'
import { TokenIssuer } from '../core/TokenIssuer'

export class RotationEngine<TPayload extends AccessTokenPayload> {
  constructor(
    private readonly options: JwtManagerOptions<TPayload>,
    private readonly issuer: TokenIssuer<TPayload>,
  ) {}

  async rotate(
    session: RefreshTokenSession<TPayload>,
    meta: SessionMeta,
  ): Promise<RefreshSuccessResult<TPayload>> {
    if (!session.accessPayload) {
      throw new JwtRefreshError(
        'Stored session is missing access payload. The refresh flow cannot issue a new access token.',
        500,
        'SESSION_PAYLOAD_MISSING',
      )
    }

    const newSessionId = randomUUID()
    const refreshToken = this.issuer.issueRefreshToken(session.userId, newSessionId, {
      parentTokenId: session.tokenId,
      originalCreatedAt: session.originalCreatedAt ?? session.createdAt,
    })
    const accessToken = this.issuer.issueAccessToken(session.accessPayload, newSessionId)
    const nextSession = this.issuer.createSessionRecord(
      newSessionId,
      session.accessPayload,
      refreshToken,
      {
        ...meta,
        deviceId: meta.deviceId ?? session.deviceId,
        ip: meta.ip ?? session.ip,
        userAgent: meta.userAgent ?? session.userAgent,
      },
      session.tokenId,
    )

    await this.options.store.createSession(nextSession)
    await this.options.store.revokeSession(session.tokenId, 'rotation')

    return {
      type: 'success',
      accessToken: accessToken.token,
      refreshToken: refreshToken.token,
      sessionId: newSessionId,
      payload: session.accessPayload,
    }
  }
}
