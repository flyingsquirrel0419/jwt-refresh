import type { AccessTokenPayload, BlacklistRecord, RefreshTokenSession, RevokedReason, TokenStore } from '../types'

interface RedisHashClient {
  hSet(key: string, values: Record<string, string>): Promise<unknown>
  hGetAll(key: string): Promise<Record<string, string>>
  expire(key: string, seconds: number): Promise<unknown>
  del(key: string): Promise<unknown>
  zAdd(key: string, values: Array<{ score: number; value: string }>): Promise<unknown>
  zRange(key: string, min: number, max: number, options?: { BY?: 'SCORE' }): Promise<string[]>
  zRem(key: string, members: string[]): Promise<unknown>
  set(key: string, value: string, options?: { EXAT?: number }): Promise<unknown>
  exists(key: string): Promise<number>
}

const KEYS = {
  session: (tokenId: string) => `jwt:session:${tokenId}`,
  userSessions: (userId: string) => `jwt:user:${userId}:sessions`,
  blacklist: (jti: string) => `jwt:blacklist:${jti}`,
}

export class RedisTokenStore<TPayload extends AccessTokenPayload = AccessTokenPayload>
  implements TokenStore<TPayload>
{
  constructor(private readonly client: RedisHashClient) {}

  async createSession(session: RefreshTokenSession<TPayload>): Promise<void> {
    const expiresAt = Math.floor(session.expiresAt.getTime() / 1000)
    await this.client.hSet(KEYS.session(session.tokenId), serializeSession(session))
    await this.client.expire(KEYS.session(session.tokenId), Math.max(expiresAt - Math.floor(Date.now() / 1000), 1))
    await this.client.zAdd(KEYS.userSessions(session.userId), [{ score: expiresAt, value: session.tokenId }])
  }

  async getSession(tokenId: string): Promise<RefreshTokenSession<TPayload> | null> {
    const values = await this.client.hGetAll(KEYS.session(tokenId))
    return Object.keys(values).length ? deserializeSession<TPayload>(values) : null
  }

  async revokeSession(tokenId: string, reason: RevokedReason = 'manual'): Promise<void> {
    const session = await this.getSession(tokenId)
    if (!session) {
      return
    }

    await this.createSession({
      ...session,
      revokedAt: new Date(),
      revokedReason: reason,
      lastUsedAt: new Date(),
    })
  }

  async revokeAllByUserId(userId: string, reason: RevokedReason = 'manual'): Promise<void> {
    const sessions = await this.getSessionsByUserId(userId)
    await Promise.all(sessions.map((session) => this.revokeSession(session.tokenId, reason)))
  }

  async getSessionsByUserId(userId: string): Promise<Array<RefreshTokenSession<TPayload>>> {
    const members = await this.client.zRange(KEYS.userSessions(userId), 0, Number.MAX_SAFE_INTEGER, { BY: 'SCORE' })
    const sessions = await Promise.all(members.map((member) => this.getSession(member)))
    return sessions.filter((session): session is RefreshTokenSession<TPayload> => Boolean(session))
  }

  async touchSession(tokenId: string, touchedAt = new Date()): Promise<void> {
    const session = await this.getSession(tokenId)
    if (!session) {
      return
    }

    await this.createSession({ ...session, lastUsedAt: touchedAt })
  }

  async blacklistToken(record: BlacklistRecord): Promise<void> {
    await this.client.set(KEYS.blacklist(record.jti), '1', { EXAT: Math.floor(record.expiresAt.getTime() / 1000) })
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    return (await this.client.exists(KEYS.blacklist(jti))) > 0
  }
}

function serializeSession<TPayload extends AccessTokenPayload>(session: RefreshTokenSession<TPayload>): Record<string, string> {
  return {
    ...Object.fromEntries(
      Object.entries(session).flatMap(([key, value]) => {
        if (value === undefined) {
          return []
        }
        if (value instanceof Date) {
          return [[key, value.toISOString()]]
        }
        return [[key, JSON.stringify(value)]]
      }),
    ),
  }
}

function deserializeSession<TPayload extends AccessTokenPayload>(
  payload: Record<string, string>,
): RefreshTokenSession<TPayload> {
  const parseDate = (value?: string) => (value ? new Date(value) : undefined)
  const requireValue = (key: string) => {
    const value = payload[key]
    if (!value) {
      throw new Error(`Missing Redis session field: ${key}`)
    }
    return value
  }
  return {
    tokenId: JSON.parse(requireValue('tokenId')) as string,
    userId: JSON.parse(requireValue('userId')) as string,
    tokenHash: JSON.parse(requireValue('tokenHash')) as string,
    deviceId: payload.deviceId ? (JSON.parse(payload.deviceId) as string) : undefined,
    userAgent: payload.userAgent ? (JSON.parse(payload.userAgent) as string) : undefined,
    ip: payload.ip ? (JSON.parse(payload.ip) as string) : undefined,
    createdAt: new Date(requireValue('createdAt')),
    lastUsedAt: new Date(requireValue('lastUsedAt')),
    expiresAt: new Date(requireValue('expiresAt')),
    revokedAt: parseDate(payload.revokedAt),
    revokedReason: payload.revokedReason ? (JSON.parse(payload.revokedReason) as RevokedReason) : undefined,
    parentTokenId: payload.parentTokenId ? (JSON.parse(payload.parentTokenId) as string) : undefined,
    metadata: payload.metadata ? (JSON.parse(payload.metadata) as Record<string, unknown>) : undefined,
    accessPayload: payload.accessPayload ? (JSON.parse(payload.accessPayload) as TPayload) : undefined,
    originalCreatedAt: parseDate(payload.originalCreatedAt),
  }
}
