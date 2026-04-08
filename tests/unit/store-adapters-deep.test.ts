import { DrizzleTokenStore } from '../../src/stores/DrizzleTokenStore'
import { PrismaTokenStore } from '../../src/stores/PrismaTokenStore'
import { RedisTokenStore } from '../../src/stores/RedisTokenStore'
import { InMemoryMutex } from '../../src/mutex/InMemoryMutex'

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

describe('adapter deep coverage', () => {
  it('covers Redis no-op paths and required-field deserialization failures', async () => {
    const { client, hashes, sortedSets } = createRedisClient()

    hashes.set('jwt:session:partial', {
      tokenId: JSON.stringify('partial'),
    })

    const store = new RedisTokenStore<TestPayload>(client)

    await expect(store.getSession('missing')).resolves.toBeNull()
    await expect(store.revokeSession('missing')).resolves.toBeUndefined()
    await expect(store.touchSession('missing')).resolves.toBeUndefined()
    await expect(store.getSession('partial')).rejects.toThrow('Missing Redis session field: userId')

    await store.getSessionsByUserId('missing-user')
    expect(sortedSets.size).toBe(0)
    expect(client.hSet).not.toHaveBeenCalled()
  })

  it('covers Redis persistence, serialization, and blacklist checks', async () => {
    const { client, hashes } = createRedisClient()
    const store = new RedisTokenStore<TestPayload>(client)
    const expiresAt = new Date(Date.now() + 60_000)

    await store.createSession({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash-1',
      deviceId: 'device-1',
      userAgent: 'agent-1',
      ip: '127.0.0.1',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
      expiresAt,
      metadata: { source: 'redis' },
      accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
      originalCreatedAt: new Date('2025-12-31T23:59:00.000Z'),
    })

    const stored = hashes.get('jwt:session:session-1')
    expect(stored).toMatchObject({
      tokenId: JSON.stringify('session-1'),
      userId: JSON.stringify('user-1'),
      tokenHash: JSON.stringify('hash-1'),
      deviceId: JSON.stringify('device-1'),
      metadata: JSON.stringify({ source: 'redis' }),
      accessPayload: JSON.stringify({ userId: 'user-1', email: 'user@example.com', roles: ['member'] }),
    })

    await store.revokeSession('session-1', 'manual')
    const revoked = await store.getSession('session-1')
    expect(revoked?.revokedReason).toBe('manual')

    await store.revokeAllByUserId('user-1', 'password_changed')
    const revokedByUser = await store.getSession('session-1')
    expect(revokedByUser?.revokedReason).toBe('password_changed')
    expect(await store.getSessionsByUserId('user-1')).toHaveLength(1)

    await store.touchSession('session-1', new Date('2026-01-01T00:00:10.000Z'))
    const touched = await store.getSession('session-1')
    expect(touched?.lastUsedAt.toISOString()).toBe('2026-01-01T00:00:10.000Z')

    await store.blacklistToken({ jti: 'jti-1', expiresAt, reason: 'manual', userId: 'user-1' })
    expect(await store.isBlacklisted('jti-1')).toBe(true)

    await store.createSession({
      tokenId: 'session-2',
      userId: 'user-2',
      tokenHash: 'hash-2',
      createdAt: new Date('2026-01-02T00:00:00.000Z'),
      lastUsedAt: new Date('2026-01-02T00:00:00.000Z'),
      expiresAt,
    })

    const minimalSession = await store.getSession('session-2')
    expect(minimalSession).toMatchObject({
      tokenId: 'session-2',
      userId: 'user-2',
      tokenHash: 'hash-2',
    })
    expect(minimalSession?.metadata).toBeUndefined()
    expect(minimalSession?.accessPayload).toBeUndefined()

    await store.createSession({
      tokenId: 'session-3',
      userId: 'user-3',
      tokenHash: 'hash-3',
      deviceId: 'device-3',
      userAgent: 'agent-3',
      ip: '10.0.0.3',
      createdAt: new Date('2026-01-03T00:00:00.000Z'),
      lastUsedAt: new Date('2026-01-03T00:00:00.000Z'),
      expiresAt,
      revokedAt: new Date('2026-01-03T00:01:00.000Z'),
      revokedReason: 'manual',
      parentTokenId: 'parent-3',
      metadata: { source: 'redis-full' },
      accessPayload: { userId: 'user-3', email: 'user3@example.com', roles: ['admin'] },
      originalCreatedAt: new Date('2026-01-02T23:59:00.000Z'),
    })

    const fullSession = await store.getSession('session-3')
    expect(fullSession).toMatchObject({
      tokenId: 'session-3',
      userId: 'user-3',
      parentTokenId: 'parent-3',
      metadata: { source: 'redis-full' },
      accessPayload: { userId: 'user-3', email: 'user3@example.com', roles: ['admin'] },
    })
  })

  it('covers Prisma serialization, null lookups, and blacklist truthy/falsey checks', async () => {
    const prisma = {
      refreshTokenSession: {
        create: vi.fn(),
        findUnique: vi.fn().mockResolvedValueOnce(null).mockResolvedValueOnce({
          tokenId: 'session-2',
          userId: 'user-2',
          tokenHash: 'hash-2',
          createdAt: new Date('2026-01-03T00:00:00.000Z'),
          lastUsedAt: new Date('2026-01-03T00:00:00.000Z'),
          expiresAt: new Date('2026-01-10T00:00:00.000Z'),
          revokedAt: null,
          revokedReason: null,
          parentTokenId: null,
          metadata: null,
          accessPayload: null,
          originalCreatedAt: null,
        }).mockResolvedValueOnce({
          tokenId: 'session-3',
          userId: 'user-3',
          tokenHash: 'hash-3',
          deviceId: 'device-3',
          userAgent: 'agent-3',
          ip: '10.0.0.3',
          createdAt: new Date('2026-01-03T00:00:00.000Z'),
          lastUsedAt: new Date('2026-01-03T00:00:00.000Z'),
          expiresAt: new Date('2026-01-10T00:00:00.000Z'),
          revokedAt: new Date('2026-01-03T00:01:00.000Z'),
          revokedReason: 'manual',
          parentTokenId: 'parent-3',
          metadata: { source: 'prisma-full' },
          accessPayload: { userId: 'user-3', email: 'user3@example.com', roles: ['admin'] },
          originalCreatedAt: new Date('2026-01-02T23:59:00.000Z'),
        }).mockResolvedValueOnce({
          tokenId: 'session-1',
          userId: 'user-1',
          tokenHash: 'hash-1',
          deviceId: 'device-1',
          userAgent: 'agent-1',
          ip: '127.0.0.1',
          createdAt: new Date('2026-01-01T00:00:00.000Z'),
          lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
          expiresAt: new Date('2026-01-08T00:00:00.000Z'),
          revokedAt: null,
          revokedReason: null,
          parentTokenId: null,
          metadata: null,
          accessPayload: null,
          originalCreatedAt: null,
        }),
        updateMany: vi.fn(),
        findMany: vi.fn().mockResolvedValue([
          {
            tokenId: 'session-1',
            userId: 'user-1',
            tokenHash: 'hash-1',
            createdAt: new Date('2026-01-01T00:00:00.000Z'),
            lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
            expiresAt: new Date('2026-01-08T00:00:00.000Z'),
            revokedAt: null,
            revokedReason: null,
            parentTokenId: null,
            metadata: { source: 'prisma' },
            accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
            originalCreatedAt: null,
          },
          {
            tokenId: 'session-2',
            userId: 'user-2',
            tokenHash: 'hash-2',
            createdAt: new Date('2026-01-03T00:00:00.000Z'),
            lastUsedAt: new Date('2026-01-03T00:00:00.000Z'),
            expiresAt: new Date('2026-01-10T00:00:00.000Z'),
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
        findUnique: vi
          .fn()
          .mockResolvedValueOnce({ expiresAt: new Date(Date.now() - 1) })
          .mockResolvedValueOnce({ expiresAt: new Date(Date.now() + 60_000) }),
      },
    }

    const store = new PrismaTokenStore<TestPayload>(prisma)
    const now = new Date('2026-01-01T00:00:00.000Z')
    const expiresAt = new Date('2026-01-08T00:00:00.000Z')

    await store.createSession({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash-1',
      deviceId: 'device-1',
      userAgent: 'agent-1',
      ip: '127.0.0.1',
      createdAt: now,
      lastUsedAt: now,
      expiresAt,
      metadata: { source: 'prisma' },
      accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
      originalCreatedAt: now,
    })

    expect(prisma.refreshTokenSession.create).toHaveBeenCalledWith({
      data: {
        tokenId: 'session-1',
        userId: 'user-1',
        tokenHash: 'hash-1',
        deviceId: 'device-1',
        userAgent: 'agent-1',
        ip: '127.0.0.1',
        createdAt: now,
        lastUsedAt: now,
        expiresAt,
        revokedAt: null,
        revokedReason: null,
        parentTokenId: null,
        metadata: { source: 'prisma' },
        accessPayload: { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
        originalCreatedAt: now,
      },
    })

    await expect(store.getSession('missing')).resolves.toBeNull()
    await expect(store.getSession('session-2')).resolves.toMatchObject({
      tokenId: 'session-2',
      userId: 'user-2',
    })
    await expect(store.getSession('session-3')).resolves.toMatchObject({
      tokenId: 'session-3',
      parentTokenId: 'parent-3',
      metadata: { source: 'prisma-full' },
    })
    await store.revokeSession('session-1', 'manual')
    await store.revokeAllByUserId('user-1', 'password_changed')
    await store.touchSession('session-1', new Date('2026-01-01T00:00:10.000Z'))

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

    const sessions = await store.getSessionsByUserId('user-1')
    expect(sessions).toHaveLength(2)
    expect(sessions[0]).toMatchObject({
      tokenId: 'session-1',
      metadata: { source: 'prisma' },
    })
    expect(sessions[1]).toMatchObject({
      tokenId: 'session-2',
    })

    const blacklistExpiresAt = new Date('2026-01-01T00:01:00.000Z')
    await store.blacklistToken({ jti: 'jti-1', expiresAt: blacklistExpiresAt, reason: 'manual' })
    expect(prisma.tokenBlacklist.upsert).toHaveBeenCalledWith({
      where: { jti: 'jti-1' },
      update: {
        expiresAt: blacklistExpiresAt,
        reason: 'manual',
        userId: undefined,
      },
      create: {
        jti: 'jti-1',
        expiresAt: blacklistExpiresAt,
        reason: 'manual',
      },
    })
    expect(await store.isBlacklisted('jti-1')).toBe(false)
    expect(await store.isBlacklisted('jti-1')).toBe(true)
  })

  it('covers Drizzle delegation and the in-memory mutex waiting path', async () => {
    const driver = {
      createSession: vi.fn(),
      getSession: vi.fn().mockResolvedValue(null),
      updateSession: vi.fn(),
      updateSessionsByUserId: vi.fn(),
      listSessionsByUserId: vi.fn().mockResolvedValue([]),
      upsertBlacklist: vi.fn(),
      getBlacklist: vi
        .fn()
        .mockResolvedValueOnce({ jti: 'jti-1', expiresAt: new Date(Date.now() - 1) })
        .mockResolvedValueOnce({ jti: 'jti-2', expiresAt: new Date(Date.now() + 60_000) }),
    }

    const store = new DrizzleTokenStore<TestPayload>(driver)
    await store.createSession({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash-1',
      createdAt: new Date(),
      lastUsedAt: new Date(),
      expiresAt: new Date(Date.now() + 60_000),
    })
    await store.revokeSession('session-1', 'manual')
    await store.revokeAllByUserId('user-1', 'password_changed')
    await store.touchSession('session-1', new Date('2026-01-01T00:00:10.000Z'))
    await store.blacklistToken({ jti: 'jti-1', expiresAt: new Date(Date.now() + 60_000) })
    expect(await store.isBlacklisted('jti-1')).toBe(false)
    expect(await store.isBlacklisted('jti-2')).toBe(true)

    const mutex = new InMemoryMutex()
    const releaseFirst = await mutex.acquire('refresh:user-1')
    let acquiredSecond = false
    const secondAcquire = mutex.acquire('refresh:user-1').then((release) => {
      acquiredSecond = true
      return release
    })

    await Promise.resolve()
    expect(acquiredSecond).toBe(false)
    expect(mutex.isLocked('refresh:user-1')).toBe(true)

    releaseFirst()
    const releaseSecond = await secondAcquire
    expect(acquiredSecond).toBe(true)
    expect(mutex.isLocked('refresh:user-1')).toBe(true)
    releaseSecond()
    expect(mutex.isLocked('refresh:user-1')).toBe(false)

    expect(driver.createSession).toHaveBeenCalledWith({
      tokenId: 'session-1',
      userId: 'user-1',
      tokenHash: 'hash-1',
      createdAt: expect.any(Date),
      lastUsedAt: expect.any(Date),
      expiresAt: expect.any(Date),
    })
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
    expect(driver.upsertBlacklist).toHaveBeenCalledWith({
      jti: 'jti-1',
      expiresAt: expect.any(Date),
    })
  })
})
