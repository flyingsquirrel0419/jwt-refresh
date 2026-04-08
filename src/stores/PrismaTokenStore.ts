import type { AccessTokenPayload, BlacklistRecord, RefreshTokenSession, RevokedReason, TokenStore } from '../types'

interface PrismaLike {
  refreshTokenSession: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>
    findUnique(args: { where: { tokenId: string } }): Promise<Record<string, unknown> | null>
    updateMany(args: { where: Record<string, unknown>; data: Record<string, unknown> }): Promise<unknown>
    findMany(args: { where: Record<string, unknown>; orderBy?: Record<string, 'asc' | 'desc'> }): Promise<Array<Record<string, unknown>>>
  }
  tokenBlacklist: {
    upsert(args: {
      where: { jti: string }
      update: Record<string, unknown>
      create: Record<string, unknown>
    }): Promise<unknown>
    findUnique(args: { where: { jti: string } }): Promise<Record<string, unknown> | null>
  }
}

export class PrismaTokenStore<TPayload extends AccessTokenPayload = AccessTokenPayload>
  implements TokenStore<TPayload>
{
  constructor(private readonly prisma: PrismaLike) {}

  async createSession(session: RefreshTokenSession<TPayload>): Promise<void> {
    await this.prisma.refreshTokenSession.create({ data: serializeSession(session) })
  }

  async getSession(tokenId: string): Promise<RefreshTokenSession<TPayload> | null> {
    const row = await this.prisma.refreshTokenSession.findUnique({ where: { tokenId } })
    return row ? deserializeSession<TPayload>(row) : null
  }

  async revokeSession(tokenId: string, reason: RevokedReason = 'manual'): Promise<void> {
    await this.prisma.refreshTokenSession.updateMany({
      where: { tokenId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason, lastUsedAt: new Date() },
    })
  }

  async revokeAllByUserId(userId: string, reason: RevokedReason = 'manual'): Promise<void> {
    await this.prisma.refreshTokenSession.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason, lastUsedAt: new Date() },
    })
  }

  async getSessionsByUserId(userId: string): Promise<Array<RefreshTokenSession<TPayload>>> {
    const rows = await this.prisma.refreshTokenSession.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    })
    return rows.map((row) => deserializeSession<TPayload>(row))
  }

  async touchSession(tokenId: string, touchedAt = new Date()): Promise<void> {
    await this.prisma.refreshTokenSession.updateMany({
      where: { tokenId },
      data: { lastUsedAt: touchedAt },
    })
  }

  async blacklistToken(record: BlacklistRecord): Promise<void> {
    await this.prisma.tokenBlacklist.upsert({
      where: { jti: record.jti },
      update: { expiresAt: record.expiresAt, reason: record.reason, userId: record.userId },
      create: { ...record },
    })
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    const row = await this.prisma.tokenBlacklist.findUnique({ where: { jti } })
    return Boolean(row && new Date(String(row.expiresAt)).getTime() > Date.now())
  }
}

function serializeSession<TPayload extends AccessTokenPayload>(session: RefreshTokenSession<TPayload>): Record<string, unknown> {
  return {
    tokenId: session.tokenId,
    userId: session.userId,
    tokenHash: session.tokenHash,
    deviceId: session.deviceId,
    userAgent: session.userAgent,
    ip: session.ip,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
    expiresAt: session.expiresAt,
    revokedAt: session.revokedAt ?? null,
    revokedReason: session.revokedReason ?? null,
    parentTokenId: session.parentTokenId ?? null,
    metadata: session.metadata ?? null,
    accessPayload: session.accessPayload ?? null,
    originalCreatedAt: session.originalCreatedAt ?? null,
  }
}

function deserializeSession<TPayload extends AccessTokenPayload>(row: Record<string, unknown>): RefreshTokenSession<TPayload> {
  return {
    tokenId: String(row.tokenId),
    userId: String(row.userId),
    tokenHash: String(row.tokenHash),
    deviceId: row.deviceId ? String(row.deviceId) : undefined,
    userAgent: row.userAgent ? String(row.userAgent) : undefined,
    ip: row.ip ? String(row.ip) : undefined,
    createdAt: new Date(String(row.createdAt)),
    lastUsedAt: new Date(String(row.lastUsedAt)),
    expiresAt: new Date(String(row.expiresAt)),
    revokedAt: row.revokedAt ? new Date(String(row.revokedAt)) : undefined,
    revokedReason: row.revokedReason ? (String(row.revokedReason) as RevokedReason) : undefined,
    parentTokenId: row.parentTokenId ? String(row.parentTokenId) : undefined,
    metadata: (row.metadata as Record<string, unknown> | null) ?? undefined,
    accessPayload: (row.accessPayload as TPayload | null) ?? undefined,
    originalCreatedAt: row.originalCreatedAt ? new Date(String(row.originalCreatedAt)) : undefined,
  }
}
