import type { AccessTokenPayload, JwtManagerOptions, RefreshResult, RequestLike, SessionMeta } from '../types'
import { JwtRefreshError } from '../errors'
import { ReuseDetector } from '../rotation/ReuseDetector'
import { RotationEngine } from '../rotation/RotationEngine'
import { hashToken, isSessionExpired } from '../utils'

const ROTATION_RACE_GRACE_MS = 1_000

export class RefreshCoordinator<TPayload extends AccessTokenPayload> {
  private readonly reuseDetector: ReuseDetector<TPayload>
  private readonly rotationEngine: RotationEngine<TPayload>

  constructor(
    private readonly options: JwtManagerOptions<TPayload>,
    rotationEngine: RotationEngine<TPayload>,
  ) {
    this.reuseDetector = new ReuseDetector(this.options.store)
    this.rotationEngine = rotationEngine
  }

  async refresh(
    verified: { userId: string; jti: string },
    refreshToken: string,
    req: RequestLike,
  ): Promise<RefreshResult<TPayload>> {
    const mutexKey = `refresh:${verified.userId}`
    const contended = this.options.mutex && typeof this.options.mutex !== 'string' && this.options.mutex.isLocked
      ? this.options.mutex.isLocked(mutexKey)
      : false

    const mutex =
      this.options.mutex && typeof this.options.mutex !== 'string'
        ? this.options.mutex
        : this.options.mutex === 'memory' || !this.options.mutex
          ? undefined
          : undefined

    const release = await (mutex?.acquire(mutexKey) ?? Promise.resolve(() => undefined))

    try {
      const session = await this.options.store.getSession(verified.jti)
      if (!session) {
        throw new JwtRefreshError('Refresh token is no longer valid', 401, 'SESSION_NOT_FOUND')
      }

      if (session.tokenHash !== hashToken(refreshToken)) {
        throw new JwtRefreshError('Refresh token is no longer valid', 401, 'SESSION_HASH_MISMATCH')
      }

      if (isSessionExpired(session)) {
        throw new JwtRefreshError('Refresh token is no longer valid', 401, 'SESSION_EXPIRED')
      }

      const absoluteExpiry = this.options.refresh.absoluteExpiry
      const originalCreatedAt = session.originalCreatedAt ?? session.createdAt
      if (
        absoluteExpiry &&
        originalCreatedAt.getTime() + requireMs(absoluteExpiry) <= Date.now()
      ) {
        await this.options.store.revokeAllByUserId(session.userId, 'absolute_expired')
        throw new JwtRefreshError('Session expired. Please log in again.', 401, 'SESSION_ABSOLUTE_EXPIRED')
      }

      if (session.revokedAt) {
        if (
          session.revokedReason === 'rotation' &&
          (contended || Date.now() - session.revokedAt.getTime() <= ROTATION_RACE_GRACE_MS)
        ) {
          return { type: 'retry' }
        }

        if (session.revokedReason === 'rotation' && (this.options.refresh.reuseDetection ?? true)) {
          const event = await this.reuseDetector.handleReuse(session, req)
          ;(this.options as JwtManagerOptions<TPayload> & { emit?: (eventName: string, ...args: unknown[]) => void }).emit?.(
            'token:reuse-detected',
            event,
          )
          this.reuseDetector.fail()
        }

        throw new JwtRefreshError('Refresh token is no longer valid', 401, 'SESSION_REVOKED')
      }

      await this.options.store.touchSession(session.tokenId)
      const result = await this.rotationEngine.rotate(session, collectSessionMeta(req))
      ;(this.options as JwtManagerOptions<TPayload> & { emit?: (eventName: string, ...args: unknown[]) => void }).emit?.(
        'token:refreshed',
        {
          userId: session.userId,
          oldTokenId: session.tokenId,
          newTokenId: result.sessionId,
          refreshedAt: new Date(),
        },
      )
      return result
    } finally {
      release()
    }
  }
}

function collectSessionMeta(req: RequestLike): SessionMeta {
  return {
    ip: req.ip,
    userAgent: req.headers['user-agent'] as string | undefined,
  }
}

function requireMs(value: string | number): number {
  if (typeof value === 'number') {
    return value * 1000
  }
  const ms = Number.parseFloat(value)
  if (!Number.isNaN(ms) && /^[0-9]+$/.test(value)) {
    return ms * 1000
  }
  const match = value.match(/^(\d+)(ms|s|m|h|d)$/)
  if (!match) {
    throw new JwtRefreshError(`Invalid absoluteExpiry: ${value}`, 500, 'INVALID_ABSOLUTE_EXPIRY')
  }

  const amount = Number.parseInt(match[1] ?? '0', 10)
  const unit = match[2]
  switch (unit) {
    case 'ms':
      return amount
    case 's':
      return amount * 1_000
    case 'm':
      return amount * 60_000
    case 'h':
      return amount * 3_600_000
    case 'd':
      return amount * 86_400_000
    default:
      throw new JwtRefreshError(`Invalid absoluteExpiry unit: ${unit}`, 500, 'INVALID_ABSOLUTE_EXPIRY')
  }
}
