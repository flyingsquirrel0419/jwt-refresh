import type { SignOptions } from 'jsonwebtoken'

import type {
  AccessTokenPayload,
  JwtManagerOptions,
  RefreshTokenSession,
  SessionMeta,
  VerifiedAccessPayload,
} from '../types'
import { addMilliseconds, createTokenId, hashToken, signJwt, ttlToMilliseconds, ttlToSeconds } from '../utils'

export class TokenIssuer<TPayload extends AccessTokenPayload> {
  constructor(private readonly options: JwtManagerOptions<TPayload>) {}

  issueAccessToken(payload: TPayload, sessionId?: string): { token: string; tokenId: string } {
    const tokenId = createTokenId()
    const claims = {
      ...payload,
      jti: tokenId,
      typ: 'access',
      ...(sessionId ? { sid: sessionId } : {}),
    }

    const signOptions: SignOptions = {
      algorithm: this.options.access.algorithm ?? 'HS256',
      expiresIn: ttlToSeconds(this.options.access.ttl),
      ...(this.options.access.issuer ? { issuer: this.options.access.issuer } : {}),
      ...(this.options.access.audience ? { audience: this.options.access.audience } : {}),
    }

    return {
      token: signJwt(claims as VerifiedAccessPayload<TPayload>, this.options.access.secret, signOptions),
      tokenId,
    }
  }

  issueRefreshToken(
    userId: string,
    sessionId: string,
    metadata: {
      parentTokenId?: string
      originalCreatedAt?: Date
    } = {},
  ): { token: string; session: Pick<RefreshTokenSession<TPayload>, 'tokenHash' | 'expiresAt' | 'originalCreatedAt'> } {
    const signOptions: SignOptions = {
      algorithm: this.options.refresh.algorithm ?? 'HS256',
      expiresIn: ttlToSeconds(this.options.refresh.ttl),
      ...(this.options.refresh.issuer ? { issuer: this.options.refresh.issuer } : {}),
      ...(this.options.refresh.audience ? { audience: this.options.refresh.audience } : {}),
    }

    const token = signJwt(
      {
        userId,
        jti: sessionId,
        typ: 'refresh',
        ...(metadata.parentTokenId ? { parentTokenId: metadata.parentTokenId } : {}),
      },
      this.options.refresh.secret,
      signOptions,
    )

    return {
      token,
      session: {
        tokenHash: hashToken(token),
        expiresAt: addMilliseconds(new Date(), ttlToMilliseconds(this.options.refresh.ttl)),
        originalCreatedAt: metadata.originalCreatedAt ?? new Date(),
      },
    }
  }

  createSessionRecord(
    sessionId: string,
    payload: TPayload,
    refreshToken: ReturnType<TokenIssuer<TPayload>['issueRefreshToken']>,
    meta: SessionMeta,
    parentTokenId?: string,
  ): RefreshTokenSession<TPayload> {
    const now = new Date()

    return {
      tokenId: sessionId,
      userId: payload.userId,
      tokenHash: refreshToken.session.tokenHash,
      deviceId: meta.deviceId,
      userAgent: meta.userAgent,
      ip: meta.ip,
      createdAt: now,
      lastUsedAt: now,
      expiresAt: refreshToken.session.expiresAt,
      parentTokenId,
      metadata: { ...meta },
      accessPayload: payload,
      originalCreatedAt: refreshToken.session.originalCreatedAt,
    }
  }
}
