import { RedlockMutex } from '../../src/mutex/RedlockMutex'
import { DrizzleTokenStore } from '../../src/stores/DrizzleTokenStore'
import { PrismaTokenStore } from '../../src/stores/PrismaTokenStore'
import { RedisTokenStore } from '../../src/stores/RedisTokenStore'

interface TestPayload {
  userId: string
  email: string
  roles: string[]
}

function createRedisClient() {
  const hashes = new Map<string, Record<string, string>>()
  const sortedSets = new Map<string, Map<string, number>>()
  const blacklists = new Map<string, number>()

  return {
    hashes,
    sortedSets,
    blacklists,
    client: {
      hSet: vi.fn(async (key: string, value: Record<string, string>) => {
        hashes.set(key, value)
      }),
      hGetAll: vi.fn(async (key: string) => hashes.get(key) ?? {}),
      expire: vi.fn(async () => undefined),
      del: vi.fn(async () => undefined),
      zAdd: vi.fn(async (key: string, values: Array<{ score: number; value: string }>) => {
        const members = sortedSets.get(key) ?? new Map<string, number>()
        for (const { score, value } of values) {
          members.set(value, score)
        }
        sortedSets.set(key, members)
      }),
      zRange: vi.fn(async (key: string, min: number, max: number) =>
        Array.from(sortedSets.get(key) ?? [])
          .filter(([, score]) => score >= min && score <= max)
          .sort((left, right) => left[1] - right[1] || left[0].localeCompare(right[0]))
          .map(([value]) => value),
      ),
      zRem: vi.fn(async (key: string, members: string[]) => {
        const sortedSet = sortedSets.get(key)
        if (!sortedSet) {
          return 0
        }

        let removed = 0
        for (const member of members) {
          if (sortedSet.delete(member)) {
            removed += 1
          }
        }

        if (sortedSet.size === 0) {
          sortedSets.delete(key)
        }

        return removed
      }),
      set: vi.fn(async (key: string, _value: string, options?: { EXAT?: number }) => {
        blacklists.set(key, options?.EXAT ?? 0)
      }),
      exists: vi.fn(async (key: string) => (blacklists.has(key) ? 1 : 0)),
    },
  }
}

describe('adapter surfaces', () => {
  it('delegates distributed locking to redlock', async () => {
    const release = vi.fn().mockResolvedValue(undefined)
    const acquire = vi.fn().mockResolvedValue({ release })
    const mutex = new RedlockMutex({ acquire }, { lockTtl: 1500 })

    const done = await mutex.acquire('refresh:user-1')
    done()

    expect(acquire).toHaveBeenCalledWith(['refresh:user-1'], 1500)
    expect(release).toHaveBeenCalled()
  })

  it('uses the drizzle driver contract for blacklist lookups', async () => {
    const driver = {
      createSession: vi.fn(),
      getSession: vi.fn(),
      updateSession: vi.fn(),
      updateSessionsByUserId: vi.fn(),
      listSessionsByUserId: vi.fn().mockResolvedValue([]),
      upsertBlacklist: vi.fn(),
      getBlacklist: vi.fn().mockResolvedValue({
        jti: 'jti-1',
        expiresAt: new Date(Date.now() + 10_000),
      }),
    }

    const store = new DrizzleTokenStore(driver)
    const result = await store.isBlacklisted('jti-1')

    expect(result).toBe(true)
    expect(driver.getBlacklist).toHaveBeenCalledWith('jti-1')
  })

  it('maps prisma rows back into refresh sessions', async () => {
    const prisma = {
      refreshTokenSession: {
        create: vi.fn(),
        findUnique: vi.fn().mockResolvedValue({
          tokenId: 'session-1',
          userId: 'user-1',
          tokenHash: 'hash',
          createdAt: new Date('2026-01-01T00:00:00.000Z'),
          lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
          expiresAt: new Date('2026-01-08T00:00:00.000Z'),
          revokedAt: null,
          revokedReason: null,
          parentTokenId: null,
          metadata: { deviceId: 'prisma' },
          accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
          originalCreatedAt: new Date('2026-01-01T00:00:00.000Z'),
        }),
        updateMany: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
      },
      tokenBlacklist: {
        upsert: vi.fn(),
        findUnique: vi.fn(),
      },
    }

    const store = new PrismaTokenStore<TestPayload>(prisma)
    const session = await store.getSession('session-1')

    expect(session).toMatchObject({
      tokenId: 'session-1',
      userId: 'user-1',
      metadata: { deviceId: 'prisma' },
    })
  })

  it('stores and reads Redis-backed blacklist entries', async () => {
    const { client } = createRedisClient()
    const store = new RedisTokenStore(client)
    await store.blacklistToken({
      jti: 'jti-1',
      expiresAt: new Date(Date.now() + 60_000),
    })

    expect(await store.isBlacklisted('jti-1')).toBe(true)
    expect(client.set).toHaveBeenCalledWith(
      'jwt:blacklist:jti-1',
      '1',
      expect.objectContaining({
        EXAT: expect.any(Number),
      }),
    )
  })

  it('returns Redis-backed sessions and supports revoke/touch flows without duplicating sorted-set members', async () => {
    const { client } = createRedisClient()
    const store = new RedisTokenStore(client)
    const future = new Date(Date.now() + 60_000)
    await store.createSession({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
      expiresAt: future,
      metadata: { source: 'redis' },
    })

    const sessions = await store.getSessionsByUserId('user-1')
    expect(sessions).toHaveLength(1)
    expect(sessions[0]).toMatchObject({ tokenId: 'session-1', metadata: { source: 'redis' } })

    await store.touchSession('session-1', new Date('2026-01-01T00:00:10.000Z'))
    await store.revokeSession('session-1', 'manual')
    const revoked = await store.getSession('session-1')
    expect(revoked?.revokedReason).toBe('manual')

    await store.revokeAllByUserId('user-1', 'password_changed')
    const allRevoked = await store.getSession('session-1')
    expect(allRevoked?.revokedReason).toBe('password_changed')
    expect(await store.getSessionsByUserId('user-1')).toHaveLength(1)
  })

  it('forwards exact Prisma session mutation payloads', async () => {
    const prisma = {
      refreshTokenSession: {
        create: vi.fn(),
        findUnique: vi.fn().mockResolvedValue(null),
        updateMany: vi.fn(),
        findMany: vi.fn().mockResolvedValue([
          {
            tokenId: 'session-1',
            userId: 'user-1',
            tokenHash: 'hash',
            createdAt: new Date('2026-01-01T00:00:00.000Z'),
            lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
            expiresAt: new Date('2026-01-08T00:00:00.000Z'),
            revokedAt: null,
            revokedReason: null,
            parentTokenId: null,
            metadata: null,
            accessPayload: null,
            originalCreatedAt: null,
          },
        ]),
      },
      tokenBlacklist: {
        upsert: vi.fn(),
        findUnique: vi.fn().mockResolvedValue({ expiresAt: new Date(Date.now() - 1) }),
      },
    }

    const store = new PrismaTokenStore<TestPayload>(prisma)
    const createdAt = new Date('2026-01-01T00:00:00.000Z')
    const expiresAt = new Date('2026-01-08T00:00:00.000Z')

    await store.createSession({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash',
      createdAt,
      lastUsedAt: createdAt,
      expiresAt,
      metadata: { source: 'prisma' },
      accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
      originalCreatedAt: createdAt,
    })
    await store.revokeSession('session-1', 'manual')
    await store.revokeAllByUserId('user-1', 'password_changed')
    await store.touchSession('session-1', new Date('2026-01-01T00:00:10.000Z'))

    expect(prisma.refreshTokenSession.create).toHaveBeenCalledWith({
      data: {
        tokenId: 'session-1',
        userId: 'user-1',
        tokenHash: 'hash',
        deviceId: undefined,
        userAgent: undefined,
        ip: undefined,
        createdAt,
        lastUsedAt: createdAt,
        expiresAt,
        revokedAt: null,
        revokedReason: null,
        parentTokenId: null,
        metadata: { source: 'prisma' },
        accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
        originalCreatedAt: createdAt,
      },
    })
    expect(prisma.refreshTokenSession.updateMany).toHaveBeenNthCalledWith(1, {
      where: { tokenId: 'session-1', revokedAt: null },
      data: {
        revokedAt: expect.any(Date),
        revokedReason: 'manual',
        lastUsedAt: expect.any(Date),
      },
    })
    expect(prisma.refreshTokenSession.updateMany).toHaveBeenNthCalledWith(2, {
      where: { userId: 'user-1', revokedAt: null },
      data: {
        revokedAt: expect.any(Date),
        revokedReason: 'password_changed',
        lastUsedAt: expect.any(Date),
      },
    })
    expect(prisma.refreshTokenSession.updateMany).toHaveBeenNthCalledWith(3, {
      where: { tokenId: 'session-1' },
      data: {
        lastUsedAt: new Date('2026-01-01T00:00:10.000Z'),
      },
    })
  })

  it('forwards exact Prisma blacklist records', async () => {
    const prisma = {
      refreshTokenSession: {
        create: vi.fn(),
        findUnique: vi.fn(),
        updateMany: vi.fn(),
        findMany: vi.fn(),
      },
      tokenBlacklist: {
        upsert: vi.fn(),
        findUnique: vi.fn().mockResolvedValue({ expiresAt: new Date(Date.now() + 60_000) }),
      },
    }

    const store = new PrismaTokenStore<TestPayload>(prisma)
    const expiresAt = new Date('2026-01-01T00:01:00.000Z')

    await store.blacklistToken({
      jti: 'jti-1',
      expiresAt,
      reason: 'manual',
      userId: 'user-1',
    })

    expect(prisma.tokenBlacklist.upsert).toHaveBeenCalledWith({
      where: { jti: 'jti-1' },
      update: {
        expiresAt,
        reason: 'manual',
        userId: 'user-1',
      },
      create: {
        jti: 'jti-1',
        expiresAt,
        reason: 'manual',
        userId: 'user-1',
      },
    })
    expect(await store.isBlacklisted('jti-1')).toBe(true)
  })

  it('forwards exact Drizzle session mutation payloads', async () => {
    const driver = {
      createSession: vi.fn().mockResolvedValue(undefined),
      getSession: vi.fn().mockResolvedValue({
        tokenId: 'session-1',
        userId: 'user-1',
        tokenHash: 'hash',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
        expiresAt: new Date('2026-01-08T00:00:00.000Z'),
      }),
      updateSession: vi.fn().mockResolvedValue(undefined),
      updateSessionsByUserId: vi.fn().mockResolvedValue(undefined),
      listSessionsByUserId: vi.fn().mockResolvedValue([]),
      upsertBlacklist: vi.fn().mockResolvedValue(undefined),
      getBlacklist: vi.fn().mockResolvedValue(null),
    }

    const store = new DrizzleTokenStore(driver)
    const createdAt = new Date('2026-01-01T00:00:00.000Z')
    const expiresAt = new Date('2026-01-08T00:00:00.000Z')

    await store.createSession({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash',
      createdAt,
      lastUsedAt: createdAt,
      expiresAt,
    })
    await store.getSession('session-1')
    await store.revokeSession('session-1', 'manual')
    await store.revokeAllByUserId('user-1', 'password_changed')
    await store.touchSession('session-1', new Date('2026-01-01T00:00:10.000Z'))
    await store.getSessionsByUserId('user-1')
    const result = await store.isBlacklisted('jti-1')

    expect(driver.createSession).toHaveBeenCalledWith({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash',
      createdAt,
      lastUsedAt: createdAt,
      expiresAt,
    })
    expect(driver.getSession).toHaveBeenCalledWith('session-1')
    expect(driver.updateSession).toHaveBeenNthCalledWith(1, 'session-1', {
      revokedAt: expect.any(Date),
      revokedReason: 'manual',
      lastUsedAt: expect.any(Date),
    })
    expect(driver.updateSession).toHaveBeenNthCalledWith(2, 'session-1', {
      lastUsedAt: new Date('2026-01-01T00:00:10.000Z'),
    })
    expect(driver.updateSessionsByUserId).toHaveBeenCalledWith('user-1', {
      revokedAt: expect.any(Date),
      revokedReason: 'password_changed',
      lastUsedAt: expect.any(Date),
    })
    expect(driver.listSessionsByUserId).toHaveBeenCalledWith('user-1')
    expect(result).toBe(false)
  })

  it('forwards exact Drizzle blacklist records', async () => {
    const driver = {
      createSession: vi.fn(),
      getSession: vi.fn().mockResolvedValue(null),
      updateSession: vi.fn(),
      updateSessionsByUserId: vi.fn(),
      listSessionsByUserId: vi.fn().mockResolvedValue([]),
      upsertBlacklist: vi.fn().mockResolvedValue(undefined),
      getBlacklist: vi.fn().mockResolvedValue({
        jti: 'jti-1',
        expiresAt: new Date(Date.now() + 10_000),
      }),
    }

    const store = new DrizzleTokenStore(driver)
    const expiresAt = new Date('2026-01-01T00:01:00.000Z')

    await store.blacklistToken({
      jti: 'jti-1',
      expiresAt,
      reason: 'manual',
      userId: 'user-1',
    })

    expect(driver.upsertBlacklist).toHaveBeenCalledWith({
      jti: 'jti-1',
      expiresAt,
      reason: 'manual',
      userId: 'user-1',
    })
    expect(await store.isBlacklisted('jti-1')).toBe(true)
  })
})
