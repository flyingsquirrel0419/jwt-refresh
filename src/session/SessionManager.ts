import type { AccessTokenPayload, SessionInfo, TokenStore } from '../types'

export class SessionManager<TPayload extends AccessTokenPayload> {
  constructor(private readonly store: TokenStore<TPayload>) {}

  async getSessions(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
    const sessions = await this.store.getSessionsByUserId(userId)
    return sessions.map((session) => ({
      sessionId: session.tokenId,
      userId: session.userId,
      deviceId: session.deviceId,
      userAgent: session.userAgent,
      ip: session.ip,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
      revokedAt: session.revokedAt,
      revokedReason: session.revokedReason,
      isCurrent: session.tokenId === currentSessionId,
    }))
  }

  async revokeSession(userId: string, sessionId: string, reason: 'logout' | 'manual' = 'manual'): Promise<void> {
    const session = await this.store.getSession(sessionId)
    if (!session || session.userId !== userId) {
      return
    }

    await this.store.revokeSession(sessionId, reason)
  }

  async revokeAllSessions(userId: string, reason: 'logout' | 'manual' | 'password_changed' = 'manual'): Promise<void> {
    await this.store.revokeAllByUserId(userId, reason)
  }
}
