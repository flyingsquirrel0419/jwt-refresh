import type { AccessTokenPayload, BlacklistRecord, RefreshTokenSession, RevokedReason, TokenStore } from '../types'

export class MemoryTokenStore<TPayload extends AccessTokenPayload = AccessTokenPayload>
  implements TokenStore<TPayload>
{
  private readonly sessions = new Map<string, RefreshTokenSession<TPayload>>()
  private readonly users = new Map<string, Set<string>>()
  private readonly blacklist = new Map<string, BlacklistRecord>()

  async createSession(session: RefreshTokenSession<TPayload>): Promise<void> {
    this.sessions.set(session.tokenId, { ...session })
    const current = this.users.get(session.userId) ?? new Set<string>()
    current.add(session.tokenId)
    this.users.set(session.userId, current)
  }

  async getSession(tokenId: string): Promise<RefreshTokenSession<TPayload> | null> {
    await this.cleanup()
    return this.sessions.get(tokenId) ?? null
  }

  async revokeSession(tokenId: string, reason: RevokedReason = 'manual'): Promise<void> {
    const session = this.sessions.get(tokenId)
    if (!session || session.revokedAt) {
      return
    }

    this.sessions.set(tokenId, {
      ...session,
      revokedAt: new Date(),
      revokedReason: reason,
      lastUsedAt: new Date(),
    })
  }

  async revokeAllByUserId(userId: string, reason: RevokedReason = 'manual'): Promise<void> {
    const tokenIds = this.users.get(userId)
    if (!tokenIds) {
      return
    }

    await Promise.all(Array.from(tokenIds, (tokenId) => this.revokeSession(tokenId, reason)))
  }

  async getSessionsByUserId(userId: string): Promise<Array<RefreshTokenSession<TPayload>>> {
    await this.cleanup()
    const tokenIds = this.users.get(userId)
    if (!tokenIds) {
      return []
    }

    return Array.from(tokenIds)
      .map((tokenId) => this.sessions.get(tokenId))
      .filter((session): session is RefreshTokenSession<TPayload> => Boolean(session))
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
  }

  async touchSession(tokenId: string, touchedAt = new Date()): Promise<void> {
    const session = this.sessions.get(tokenId)
    if (!session) {
      return
    }

    this.sessions.set(tokenId, {
      ...session,
      lastUsedAt: touchedAt,
    })
  }

  async blacklistToken(record: BlacklistRecord): Promise<void> {
    this.blacklist.set(record.jti, record)
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    await this.cleanup()
    return this.blacklist.has(jti)
  }

  async cleanup(): Promise<void> {
    const now = Date.now()

    for (const [tokenId, session] of this.sessions.entries()) {
      if (session.expiresAt.getTime() <= now) {
        this.sessions.delete(tokenId)
        this.users.get(session.userId)?.delete(tokenId)
      }
    }

    for (const [jti, record] of this.blacklist.entries()) {
      if (record.expiresAt.getTime() <= now) {
        this.blacklist.delete(jti)
      }
    }
  }
}
