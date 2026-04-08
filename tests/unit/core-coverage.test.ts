import { sign, verify } from 'jsonwebtoken'

import { JwtRefreshError } from '../../src/errors'
import { JwtManager } from '../../src/core/JwtManager'
import { RefreshCoordinator } from '../../src/core/RefreshCoordinator'
import { TokenIssuer } from '../../src/core/TokenIssuer'
import { createRefreshHandler } from '../../src/middleware/refreshHandler'
import { RotationEngine } from '../../src/rotation/RotationEngine'
import { BlacklistManager } from '../../src/session/BlacklistManager'
import { SessionManager } from '../../src/session/SessionManager'
import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'
import type {
  AccessTokenPayload,
  JwtManagerOptions,
  RefreshTokenSession,
  TokenStore,
} from '../../src/types'

interface TestPayload extends AccessTokenPayload {
  email: string
  roles: string[]
}

const payload: TestPayload = {
  userId: 'user-1',
  email: 'user@example.com',
  roles: ['member'],
}

function createStore(
  overrides: Partial<TokenStore<TestPayload>> = {},
): TokenStore<TestPayload> & Record<string, unknown> {
  return {
    createSession: vi.fn().mockResolvedValue(undefined),
    getSession: vi.fn().mockResolvedValue(null),
    revokeSession: vi.fn().mockResolvedValue(undefined),
    revokeAllByUserId: vi.fn().mockResolvedValue(undefined),
    getSessionsByUserId: vi.fn().mockResolvedValue([]),
    touchSession: vi.fn().mockResolvedValue(undefined),
    blacklistToken: vi.fn().mockResolvedValue(undefined),
    isBlacklisted: vi.fn().mockResolvedValue(false),
    ...overrides,
  }
}

function createManager(
  store: TokenStore<TestPayload>,
  overrides: Partial<JwtManagerOptions<TestPayload>> = {},
) {
  return new JwtManager<TestPayload>({
    access: {
      secret: 'access-secret',
      ttl: '15m',
    },
    refresh: {
      secret: 'refresh-secret',
      ttl: '7d',
      rotation: true,
      reuseDetection: true,
      absoluteExpiry: '90d',
    },
    store,
    ...overrides,
  })
}

function createIssuer() {
  return new TokenIssuer<TestPayload>({
    access: {
      secret: 'access-secret',
      ttl: '15m',
    },
    refresh: {
      secret: 'refresh-secret',
      ttl: '7d',
      rotation: true,
      reuseDetection: true,
      absoluteExpiry: '90d',
    },
    store: createStore(),
  })
}

function createRefreshSession(
  overrides: Partial<RefreshTokenSession<TestPayload>> = {},
) {
  const issuer = createIssuer()
  const tokenId = overrides.tokenId ?? 'session-1'
  const originalCreatedAt = overrides.originalCreatedAt
  const issued = issuer.issueRefreshToken(overrides.userId ?? payload.userId, tokenId, {
    originalCreatedAt,
    parentTokenId: overrides.parentTokenId,
  })

  return {
    token: issued.token,
    session: {
      tokenId,
      userId: overrides.userId ?? payload.userId,
      tokenHash: overrides.tokenHash ?? issued.session.tokenHash,
      deviceId: overrides.deviceId,
      userAgent: overrides.userAgent,
      ip: overrides.ip,
      createdAt: overrides.createdAt ?? new Date(),
      lastUsedAt: overrides.lastUsedAt ?? new Date(),
      expiresAt: overrides.expiresAt ?? issued.session.expiresAt,
      revokedAt: overrides.revokedAt,
      revokedReason: overrides.revokedReason,
      parentTokenId: overrides.parentTokenId,
      metadata: overrides.metadata,
      accessPayload: overrides.accessPayload,
      originalCreatedAt: issued.session.originalCreatedAt,
    } satisfies RefreshTokenSession<TestPayload>,
  }
}

function createCoordinator(
  session: RefreshTokenSession<TestPayload> | null,
  overrides: {
    mutex?: JwtManagerOptions<TestPayload>['mutex']
    refresh?: Partial<JwtManagerOptions<TestPayload>['refresh']>
  } = {},
) {
  const store = createStore({
    getSession: vi.fn().mockResolvedValue(session),
    touchSession: vi.fn().mockResolvedValue(undefined),
    revokeAllByUserId: vi.fn().mockResolvedValue(undefined),
    createSession: vi.fn().mockResolvedValue(undefined),
    revokeSession: vi.fn().mockResolvedValue(undefined),
  })

  const emit = vi.fn()
  const options: JwtManagerOptions<TestPayload> & { emit: typeof emit } = {
    access: {
      secret: 'access-secret',
      ttl: '15m',
    },
    refresh: {
      secret: 'refresh-secret',
      ttl: '7d',
      rotation: true,
      reuseDetection: true,
      absoluteExpiry: '90d',
      ...overrides.refresh,
    },
    store,
    mutex: overrides.mutex,
    emit,
  }
  const rotationEngine = {
    rotate: vi.fn(),
  } as unknown as RotationEngine<TestPayload>

  return {
    emit,
    options,
    rotationEngine,
    store,
    coordinator: new RefreshCoordinator(options, rotationEngine),
  }
}

describe('core coverage', () => {
  it('rejects refresh-token verification when the stored hash does not match', async () => {
    const tokenId = 'session-1'
    const token = sign(
      {
        userId: payload.userId,
        jti: tokenId,
        typ: 'refresh',
      },
      'refresh-secret',
      { expiresIn: '1h' },
    )
    const jwt = createManager(
      createStore({
        getSession: vi.fn().mockResolvedValue({
          tokenId,
          userId: payload.userId,
          tokenHash: 'different-hash',
          createdAt: new Date(),
          lastUsedAt: new Date(),
          expiresAt: new Date(Date.now() + 60_000),
        }),
      }),
    )

    await expect(jwt.verifyRefreshToken(token)).rejects.toMatchObject({
      code: 'SESSION_NOT_FOUND',
      message: 'Refresh token is no longer valid',
    })
  })

  it('rejects refresh-token verification when the session is missing', async () => {
    const token = sign(
      {
        userId: payload.userId,
        jti: 'missing-session',
        typ: 'refresh',
      },
      'refresh-secret',
      { expiresIn: '1h' },
    )
    const jwt = createManager(createStore())

    await expect(jwt.verifyRefreshToken(token)).rejects.toMatchObject({
      code: 'SESSION_NOT_FOUND',
      message: 'Refresh token is no longer valid',
    })
  })

  it('emits revocation events for a single session and all sessions', async () => {
    const store = new MemoryTokenStore<TestPayload>()
    const jwt = createManager(store)
    const events: Array<{ tokenId: string; reason: string }> = []
    jwt.on('token:revoked', (event) => {
      events.push({ tokenId: event.tokenId, reason: event.reason })
    })

    const first = await jwt.signRefreshToken(payload.userId)
    const second = await jwt.signRefreshToken(payload.userId)

    const sessionsBefore = await jwt.getSessions(payload.userId)
    const currentId = sessionsBefore[0]?.sessionId

    await jwt.revokeSession(payload.userId, sessionsBefore[1]?.sessionId ?? second)
    await jwt.revokeAllSessions(payload.userId)

    expect(events.map((event) => event.reason)).toEqual(['manual', 'manual', 'manual'])
    expect(events.map((event) => event.tokenId)).toEqual(
      expect.arrayContaining([currentId ?? first, sessionsBefore[1]?.sessionId ?? second]),
    )

    const sessionsAfter = await jwt.getSessions(payload.userId, currentId)
    expect(sessionsAfter.find((session) => session.sessionId === currentId)?.isCurrent).toBe(true)
  })

  it('returns cookie helpers using custom refresh cookie settings', () => {
    const jwt = createManager(
      createStore(),
      {
        cookie: {
          name: 'sessionRefresh',
          path: '/auth',
          sameSite: 'lax',
        },
      },
    )

    expect(jwt.getCookieOptions()).toMatchObject({
      name: 'sessionRefresh',
      path: '/auth',
      sameSite: 'lax',
    })
    expect(
      jwt.getRefreshCookie({
        headers: { cookie: 'sessionRefresh=cookie-value' },
      }),
    ).toBe('cookie-value')
  })

  it('uses a custom mutex adapter while coordinating a refresh', async () => {
    const { token, session } = createRefreshSession({
      accessPayload: payload,
    })
    const release = vi.fn()
    const mutex = {
      acquire: vi.fn().mockResolvedValue(release),
      isLocked: vi.fn().mockReturnValue(false),
    }
    const { coordinator, rotationEngine } = createCoordinator(session, { mutex })
    vi.mocked(rotationEngine.rotate).mockResolvedValue({
      type: 'success',
      accessToken: 'next-access-token',
      refreshToken: 'next-refresh-token',
      sessionId: 'next-session-id',
      payload,
    })

    await expect(
      coordinator.refresh(
        { userId: session.userId, jti: session.tokenId },
        token,
        {
          headers: { 'user-agent': 'mutex-agent' },
          ip: '127.0.0.1',
        },
      ),
    ).resolves.toEqual({
      type: 'success',
      accessToken: 'next-access-token',
      refreshToken: 'next-refresh-token',
      sessionId: 'next-session-id',
      payload,
    })

    expect(mutex.isLocked).toHaveBeenCalledWith(`refresh:${session.userId}`)
    expect(mutex.acquire).toHaveBeenCalledWith(`refresh:${session.userId}`)
    expect(release).toHaveBeenCalled()
    expect(rotationEngine.rotate).toHaveBeenCalledWith(
      expect.objectContaining({
        tokenId: session.tokenId,
        userId: session.userId,
      }),
      expect.objectContaining({
        userAgent: 'mutex-agent',
        ip: '127.0.0.1',
      }),
    )
  })

  it('signs access tokens with the configured issuer and audience', () => {
    const jwt = createManager(createStore(), {
      access: {
        secret: 'access-secret',
        ttl: '15m',
        issuer: 'access-issuer',
        audience: ['aud-a', 'aud-b'],
      },
      refresh: {
        secret: 'refresh-secret',
        ttl: '7d',
        rotation: true,
        reuseDetection: true,
      },
    })

    const token = jwt.signAccessToken(payload)
    const claims = verify(token, 'access-secret', {
      issuer: 'access-issuer',
      audience: ['aud-a', 'aud-b'],
    }) as Record<string, unknown>

    expect(jwt.verifyAccessToken(token)).toMatchObject(payload)
    expect(claims).toMatchObject({
      userId: payload.userId,
      typ: 'access',
      iss: 'access-issuer',
      aud: ['aud-a', 'aud-b'],
    })
    expect(() =>
      verify(token, 'access-secret', {
        issuer: 'wrong-issuer',
      }),
    ).toThrow()
  })

  it('issues refresh tokens with the configured issuer and audience', async () => {
    const jwt = createManager(new MemoryTokenStore<TestPayload>(), {
      access: {
        secret: 'access-secret',
        ttl: '15m',
      },
      refresh: {
        secret: 'refresh-secret',
        ttl: '7d',
        rotation: true,
        reuseDetection: true,
        issuer: 'refresh-issuer',
        audience: 'refresh-aud',
      },
    })

    const issued = await jwt.issueTokens(
      {
        setHeader: vi.fn(),
      },
      payload,
    )
    const claims = verify(issued.refreshToken, 'refresh-secret', {
      issuer: 'refresh-issuer',
      audience: 'refresh-aud',
    }) as Record<string, unknown>

    expect(claims).toMatchObject({
      userId: payload.userId,
      typ: 'refresh',
      iss: 'refresh-issuer',
      aud: 'refresh-aud',
    })
    await expect(jwt.verifyRefreshToken(issued.refreshToken)).resolves.toMatchObject({
      userId: payload.userId,
      typ: 'refresh',
    })
  })

  it('rejects invalid access and refresh tokens', async () => {
    const jwt = createManager(createStore())

    expect(() => jwt.verifyAccessToken('not-a-token')).toThrow(JwtRefreshError)
    await expect(jwt.verifyRefreshToken('not-a-token')).rejects.toMatchObject({
      code: 'REFRESH_TOKEN_INVALID',
    })
  })

  it('blacklists access tokens only when they include an expiration', async () => {
    const jwt = createManager(createStore())
    const tokenWithoutExp = sign(
      {
        userId: payload.userId,
        jti: 'access-1',
        typ: 'access',
      },
      'access-secret',
    )

    await expect(jwt.blacklistToken(tokenWithoutExp)).rejects.toMatchObject({
      code: 'ACCESS_TOKEN_EXP_MISSING',
      message: 'Access token is missing an expiration',
    })
  })

  it('uses the default refresh buffer and respects explicit blacklist user ids', async () => {
    const blacklistToken = vi.fn().mockResolvedValue(undefined)
    const jwt = createManager(
      createStore({
        blacklistToken,
      }),
    )
    const token = jwt.signAccessToken(payload)

    expect(jwt.getRefreshBuffer()).toBe(0)
    await jwt.blacklistToken(token)
    await jwt.blacklistToken(token, { userId: 'override-user' })
    expect(blacklistToken).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'override-user',
      }),
    )
  })

  it('emits store errors and rejects on the default warn path', async () => {
    const error = new Error('create failed')
    const store = createStore({
      createSession: vi.fn().mockRejectedValue(error),
    })
    const jwt = createManager(store)
    const storeErrors: Error[] = []
    jwt.on('store:error', (caught) => storeErrors.push(caught))

    await expect(jwt.issueTokens({ setHeader: vi.fn() }, payload)).rejects.toThrow('create failed')
    expect(storeErrors).toHaveLength(1)
    expect(storeErrors[0]).toBe(error)
  })

  it('normalizes non-Error store failures', async () => {
    const store = createStore({
      createSession: vi.fn().mockRejectedValue('boom'),
    })
    const jwt = createManager(store)
    const storeErrors: Error[] = []
    jwt.on('store:error', (caught) => storeErrors.push(caught))

    await expect(jwt.signRefreshToken(payload.userId)).rejects.toThrow('boom')
    expect(storeErrors).toHaveLength(1)
    expect(storeErrors[0]).toBeInstanceOf(Error)
    expect(storeErrors[0]?.message).toBe('boom')
  })

  it('emits store errors and throws on the explicit throw path', async () => {
    const error = new Error('persist failed')
    const store = createStore({
      createSession: vi.fn().mockRejectedValue(error),
    })
    const jwt = createManager(store, { onStoreError: 'throw' })
    const storeErrors: Error[] = []
    jwt.on('store:error', (caught) => storeErrors.push(caught))

    await expect(jwt.signRefreshToken(payload.userId)).rejects.toThrow('persist failed')
    expect(storeErrors).toHaveLength(1)
    expect(storeErrors[0]).toBe(error)
  })

  it('maps the current session id when listing sessions', async () => {
    const store = new SessionManager<TestPayload>(createStore({
      getSessionsByUserId: vi.fn().mockResolvedValue([
        {
          tokenId: 'session-a',
          userId: payload.userId,
          tokenHash: 'hash-a',
          createdAt: new Date('2026-01-01T00:00:00.000Z'),
          lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
          expiresAt: new Date('2026-01-02T00:00:00.000Z'),
        },
        {
          tokenId: 'session-b',
          userId: payload.userId,
          tokenHash: 'hash-b',
          createdAt: new Date('2026-01-02T00:00:00.000Z'),
          lastUsedAt: new Date('2026-01-02T00:00:00.000Z'),
          expiresAt: new Date('2026-01-03T00:00:00.000Z'),
        },
      ]),
    }))

    const sessions = await store.getSessions(payload.userId, 'session-b')
    expect(sessions).toMatchObject([
      { sessionId: 'session-a', isCurrent: false },
      { sessionId: 'session-b', isCurrent: true },
    ])
  })

  it('treats session revocation as a no-op when the owner does not match', async () => {
    const revokeSession = vi.fn().mockResolvedValue(undefined)
    const store = createStore({
      getSession: vi.fn().mockResolvedValue({
        tokenId: 'session-a',
        userId: 'other-user',
        tokenHash: 'hash',
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      }),
      revokeSession,
    })
    const manager = new SessionManager<TestPayload>(store)

    await manager.revokeSession(payload.userId, 'session-a')
    expect(revokeSession).not.toHaveBeenCalled()
  })

  it('delegates session revocation for all sessions to the store', async () => {
    const revokeAllByUserId = vi.fn().mockResolvedValue(undefined)
    const manager = new SessionManager<TestPayload>(
      createStore({
        revokeAllByUserId,
      }),
    )

    await manager.revokeAllSessions(payload.userId, 'password_changed')
    expect(revokeAllByUserId).toHaveBeenCalledWith(payload.userId, 'password_changed')
  })

  it('rejects expired blacklist records and delegates lookups', async () => {
    const blacklistToken = vi.fn().mockResolvedValue(undefined)
    const isBlacklisted = vi.fn().mockResolvedValue(true)
    const manager = new BlacklistManager<TestPayload>(
      createStore({
        blacklistToken,
        isBlacklisted,
      }),
    )

    await expect(
      manager.blacklist({
        jti: 'jti-1',
        expiresAt: new Date(Date.now() - 1),
      }),
    ).rejects.toMatchObject({
      code: 'TOKEN_ALREADY_EXPIRED',
      message: 'Cannot blacklist an expired access token',
    })

    expect(blacklistToken).not.toHaveBeenCalled()
    await expect(manager.isBlacklisted('jti-1')).resolves.toBe(true)
  })

  it('returns a 401 refresh response when the cookie is missing', async () => {
    const jwt = {
      getRefreshCookie: vi.fn().mockReturnValue(null),
      refreshToken: vi.fn(),
      getCookieOptions: vi.fn(),
    } as unknown as JwtManager<TestPayload>
    const response = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    }
    const handler = createRefreshHandler(jwt, {})

    await handler({ headers: {} }, response, vi.fn())

    expect(response.status).toHaveBeenCalledWith(401)
    expect(response.json).toHaveBeenCalledWith({
      error: 'Missing refresh token',
      code: 'REFRESH_TOKEN_MISSING',
    })
  })

  it('throws when rotating a session without an access payload', async () => {
    const store = createStore()
    const issuer = createIssuer()
    const options: JwtManagerOptions<TestPayload> = {
      access: {
        secret: 'access-secret',
        ttl: '15m',
      },
      refresh: {
        secret: 'refresh-secret',
        ttl: '7d',
        rotation: true,
      },
      store,
    }
    const engine = new RotationEngine<TestPayload>(options, issuer)
    const { session } = createRefreshSession({
      accessPayload: undefined,
    })

    await expect(engine.rotate(session, {})).rejects.toMatchObject({
      code: 'SESSION_PAYLOAD_MISSING',
      message: 'Stored session is missing access payload. The refresh flow cannot issue a new access token.',
    })
  })

  it('reuses session metadata when the refresh request omits request context', async () => {
    const store = createStore()
    const issuer = createIssuer()
    const options = {
      access: {
        secret: 'access-secret',
        ttl: '15m',
      },
      refresh: {
        secret: 'refresh-secret',
        ttl: '7d',
        rotation: true,
        reuseDetection: true,
      },
      store,
    } satisfies JwtManagerOptions<TestPayload>
    const engine = new RotationEngine<TestPayload>(options, issuer)
    const session = createRefreshSession({
      accessPayload: payload,
      deviceId: 'device-1',
      ip: '127.0.0.1',
      userAgent: 'session-agent',
    }).session

    await engine.rotate(session, {})

    expect(store.createSession).toHaveBeenCalledWith(
      expect.objectContaining({
        deviceId: 'device-1',
        ip: '127.0.0.1',
        userAgent: 'session-agent',
        parentTokenId: session.tokenId,
      }),
    )
  })

  it('returns retry when a revoked rotation session is still in the grace window', async () => {
    const now = new Date('2026-04-08T00:00:00.000Z')
    vi.useFakeTimers()
    vi.setSystemTime(now)

    try {
      const { token, session } = createRefreshSession({
        accessPayload: payload,
        revokedAt: new Date(now.getTime() - 500),
        revokedReason: 'rotation',
      })
      const mutex = {
        isLocked: vi.fn().mockReturnValue(false),
        acquire: vi.fn().mockResolvedValue(vi.fn()),
      }
      const { coordinator, rotationEngine } = createCoordinator(session, { mutex })

      await expect(
        coordinator.refresh(
          { userId: session.userId, jti: session.tokenId },
          token,
          {
            headers: { 'user-agent': 'test-agent' },
            ip: '127.0.0.1',
          },
        ),
      ).resolves.toEqual({ type: 'retry' })

      expect(rotationEngine.rotate).not.toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  it('returns retry when a revoked rotation session is contended by the mutex', async () => {
    const { token, session } = createRefreshSession({
      accessPayload: payload,
      revokedAt: new Date(Date.now() - 5_000),
      revokedReason: 'rotation',
    })
    const mutex = {
      isLocked: vi.fn().mockReturnValue(true),
      acquire: vi.fn().mockResolvedValue(vi.fn()),
    }
    const { coordinator, rotationEngine } = createCoordinator(session, { mutex })

    await expect(
      coordinator.refresh(
        { userId: session.userId, jti: session.tokenId },
        token,
        {
          headers: { 'user-agent': 'test-agent' },
          ip: '127.0.0.1',
        },
      ),
    ).resolves.toEqual({ type: 'retry' })

    expect(rotationEngine.rotate).not.toHaveBeenCalled()
  })

  it('rejects rotation-revoked sessions without reuse detection', async () => {
    const { token, session } = createRefreshSession({
      accessPayload: payload,
      revokedAt: new Date(Date.now() - 5_000),
      revokedReason: 'rotation',
    })
    const { coordinator, store, emit, rotationEngine } = createCoordinator(session, {
      refresh: {
        reuseDetection: false,
      },
    })

    await expect(
      coordinator.refresh(
        { userId: session.userId, jti: session.tokenId },
        token,
        {
          headers: { 'user-agent': 'test-agent' },
          ip: '127.0.0.1',
        },
      ),
    ).rejects.toMatchObject({
      code: 'SESSION_REVOKED',
      message: 'Refresh token is no longer valid',
    })

    expect(store.revokeAllByUserId).not.toHaveBeenCalled()
    expect(emit).not.toHaveBeenCalled()
    expect(rotationEngine.rotate).not.toHaveBeenCalled()
  })

  it('detects refresh-token reuse and revokes every active session', async () => {
    const { token, session } = createRefreshSession({
      accessPayload: payload,
      revokedAt: new Date(Date.now() - 5_000),
      revokedReason: 'rotation',
    })
    const { coordinator, store, emit, rotationEngine } = createCoordinator(session)

    await expect(
      coordinator.refresh(
        { userId: session.userId, jti: session.tokenId },
        token,
        {
          headers: { 'user-agent': 'reuse-agent' },
          ip: '127.0.0.1',
        },
      ),
    ).rejects.toMatchObject({
      code: 'REFRESH_TOKEN_REUSED',
      message: 'Refresh token reuse detected',
    })

    expect(store.revokeAllByUserId).toHaveBeenCalledWith(session.userId, 'reuse_detected')
    expect(emit).toHaveBeenCalledWith(
      'token:reuse-detected',
      expect.objectContaining({
        userId: session.userId,
        tokenId: session.tokenId,
        ip: '127.0.0.1',
        userAgent: 'reuse-agent',
      }),
    )
    expect(rotationEngine.rotate).not.toHaveBeenCalled()
  })

  it.each([
    ['numeric', 1],
    ['numeric string', '1'],
    ['minute', '1m'],
    ['hour', '1h'],
  ] as const)(
    'enforces absolute expiry for %s',
    async (_label, absoluteExpiry) => {
      const oldDate = new Date(Date.now() - 2 * 60 * 60 * 1_000)
      const { token, session: expiredSession } = createRefreshSession({
        accessPayload: payload,
        originalCreatedAt: oldDate,
      })

      const { coordinator, store } = createCoordinator(expiredSession, {
        refresh: {
          absoluteExpiry,
        },
      })

      await expect(
        coordinator.refresh(
          { userId: expiredSession.userId, jti: expiredSession.tokenId },
          token,
          {
            headers: { 'user-agent': 'abs-agent' },
            ip: '127.0.0.1',
          },
        ),
      ).rejects.toMatchObject({
        code: 'SESSION_ABSOLUTE_EXPIRED',
        message: 'Session expired. Please log in again.',
      })

      expect(store.revokeAllByUserId).toHaveBeenCalledWith(expiredSession.userId, 'absolute_expired')
    },
  )

  it('rejects invalid absolute expiry values', async () => {
    const oldDate = new Date(Date.now() - 2 * 60 * 60 * 1_000)
    const { token, session: expiredSession } = createRefreshSession({
      accessPayload: payload,
      originalCreatedAt: oldDate,
    })
    const { coordinator } = createCoordinator(expiredSession, {
      refresh: {
        absoluteExpiry: 'bad-value',
      },
    })

    await expect(
      coordinator.refresh(
        { userId: expiredSession.userId, jti: expiredSession.tokenId },
        token,
        {
          headers: { 'user-agent': 'abs-agent' },
          ip: '127.0.0.1',
        },
      ),
    ).rejects.toMatchObject({
      code: 'INVALID_ABSOLUTE_EXPIRY',
      message: 'Invalid absoluteExpiry: bad-value',
    })
  })

  it('rejects refresh requests when the stored session is missing or the hash mismatches', async () => {
    const token = createRefreshSession().token
    const missing = createCoordinator(null)
    await expect(
      missing.coordinator.refresh(
        { userId: payload.userId, jti: 'missing-session' },
        token,
        { headers: {} },
      ),
    ).rejects.toMatchObject({
      code: 'SESSION_NOT_FOUND',
    })

    const { token: mismatchToken, session: mismatchSession } = createRefreshSession({
      tokenHash: 'different',
    })
    const mismatch = createCoordinator(mismatchSession)
    await expect(
      mismatch.coordinator.refresh(
        { userId: mismatchSession.userId, jti: mismatchSession.tokenId },
        mismatchToken,
        { headers: {} },
      ),
    ).rejects.toMatchObject({
      code: 'SESSION_HASH_MISMATCH',
    })
  })

  it('rejects expired refresh sessions before rotation starts', async () => {
    const { token, session } = createRefreshSession({
      accessPayload: payload,
      expiresAt: new Date(Date.now() - 1_000),
    })
    const coordinator = createCoordinator(session)

    await expect(
      coordinator.coordinator.refresh(
        { userId: session.userId, jti: session.tokenId },
        token,
        { headers: {} },
      ),
    ).rejects.toMatchObject({
      code: 'SESSION_EXPIRED',
    })
  })
})
