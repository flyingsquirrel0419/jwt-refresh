import type { AccessTokenPayload, BlacklistRecord, RefreshTokenSession, RevokedReason, TokenStore } from '../types'

interface DrizzleDriver<TPayload extends AccessTokenPayload> {
  createSession(session: RefreshTokenSession<TPayload>): Promise<void>
  getSession(tokenId: string): Promise<RefreshTokenSession<TPayload> | null>
  updateSession(tokenId: string, changes: Partial<RefreshTokenSession<TPayload>>): Promise<void>
  updateSessionsByUserId(userId: string, changes: Partial<RefreshTokenSession<TPayload>>): Promise<void>
  listSessionsByUserId(userId: string): Promise<Array<RefreshTokenSession<TPayload>>>
  upsertBlacklist(record: BlacklistRecord): Promise<void>
  getBlacklist(jti: string): Promise<BlacklistRecord | null>
}

export class DrizzleTokenStore<TPayload extends AccessTokenPayload = AccessTokenPayload>
  implements TokenStore<TPayload>
{
  constructor(private readonly driver: DrizzleDriver<TPayload>) {}

  createSession(session: RefreshTokenSession<TPayload>): Promise<void> {
    return this.driver.createSession(session)
  }

  getSession(tokenId: string): Promise<RefreshTokenSession<TPayload> | null> {
    return this.driver.getSession(tokenId)
  }

  revokeSession(tokenId: string, reason: RevokedReason = 'manual'): Promise<void> {
    return this.driver.updateSession(tokenId, {
      revokedAt: new Date(),
      revokedReason: reason,
      lastUsedAt: new Date(),
    })
  }

  revokeAllByUserId(userId: string, reason: RevokedReason = 'manual'): Promise<void> {
    return this.driver.updateSessionsByUserId(userId, {
      revokedAt: new Date(),
      revokedReason: reason,
      lastUsedAt: new Date(),
    })
  }

  getSessionsByUserId(userId: string): Promise<Array<RefreshTokenSession<TPayload>>> {
    return this.driver.listSessionsByUserId(userId)
  }

  touchSession(tokenId: string, touchedAt = new Date()): Promise<void> {
    return this.driver.updateSession(tokenId, { lastUsedAt: touchedAt })
  }

  blacklistToken(record: BlacklistRecord): Promise<void> {
    return this.driver.upsertBlacklist(record)
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    const row = await this.driver.getBlacklist(jti)
    return Boolean(row && row.expiresAt.getTime() > Date.now())
  }
}
