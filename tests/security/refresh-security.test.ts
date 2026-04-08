import express from 'express'
import request from 'supertest'
import { afterEach, beforeEach, vi } from 'vitest'

import { JwtManager } from '../../src/index'
import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'

interface TestPayload {
  userId: string
  email: string
  roles: string[]
}

function readRefreshCookie(header: string | string[] | undefined): string {
  const values = Array.isArray(header) ? header : [header ?? '']
  const entry = values
    .flatMap((value) => value.split(';'))
    .map((value) => value.trim())
    .find((value) => value.startsWith('refreshToken='))

  if (!entry) {
    throw new Error('refreshToken cookie missing')
  }

  return entry
}

function setup(overrides: { refreshTtl?: string } = {}) {
  const jwt = new JwtManager<TestPayload>({
    access: {
      secret: 'access-secret',
      ttl: '15m',
    },
    refresh: {
      secret: 'refresh-secret',
      ttl: overrides.refreshTtl ?? '7d',
      rotation: true,
      reuseDetection: true,
      absoluteExpiry: '90d',
    },
    cookie: {
      path: '/auth',
    },
    store: new MemoryTokenStore(),
  })

  const app = express()
  app.use(express.json())

  app.post('/auth/login', async (_req, res) => {
    const tokens = await jwt.issueTokens(
      res,
      {
        userId: 'user-1',
        email: 'user@example.com',
        roles: ['member'],
      },
      {
        deviceId: 'device-1',
        ip: '127.0.0.1',
        userAgent: 'vitest',
      },
    )

    res.json(tokens)
  })

  app.post('/auth/refresh', jwt.refreshHandler())

  return { jwt, app }
}

describe('refresh security behavior', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('treats simultaneous refresh attempts as a race, not token theft', async () => {
    const { app } = setup()
    const login = await request(app).post('/auth/login').expect(200)
    const cookie = readRefreshCookie(login.headers['set-cookie'])

    const responses = await Promise.all(
      Array.from({ length: 10 }, () => request(app).post('/auth/refresh').set('Cookie', cookie)),
    )

    const statuses = responses.map((response) => response.status)
    const unauthorized = statuses.filter((status) => status === 401)
    const success = statuses.filter((status) => status === 200)
    const retries = statuses.filter((status) => status === 409)

    expect(unauthorized).toHaveLength(0)
    expect(success.length).toBeGreaterThanOrEqual(1)
    expect(retries.length).toBeGreaterThanOrEqual(1)
    expect(
      responses
        .filter((response) => response.status === 409)
        .every((response) => response.headers['x-refresh-retry'] === 'true'),
    ).toBe(true)
  })

  it('detects actual refresh-token reuse and revokes all active sessions', async () => {
    const { app, jwt } = setup()
    const reuseEvents: Array<{ userId: string; tokenId: string }> = []
    jwt.on('token:reuse-detected', (event) => {
      reuseEvents.push({ userId: event.userId, tokenId: event.tokenId })
    })

    const login = await request(app).post('/auth/login').expect(200)
    const cookie = readRefreshCookie(login.headers['set-cookie'])

    await request(app).post('/auth/refresh').set('Cookie', cookie).expect(200)
    vi.setSystemTime(new Date('2026-01-01T00:00:02.000Z'))

    const replay = await request(app).post('/auth/refresh').set('Cookie', cookie).expect(401)

    expect(replay.body.error).toBe('Refresh token reuse detected')
    expect(reuseEvents).toHaveLength(1)
    expect(reuseEvents[0]?.userId).toBe('user-1')

    const sessions = await jwt.getSessions('user-1')
    expect(sessions.length).toBeGreaterThanOrEqual(2)
    expect(sessions.every((session) => session.revokedAt instanceof Date)).toBe(true)
  })

  it('enforces absolute expiry across rotated sessions', async () => {
    const { app } = setup({ refreshTtl: '30d' })
    const login = await request(app).post('/auth/login').expect(200)
    let cookie = readRefreshCookie(login.headers['set-cookie'])

    for (const timestamp of [
      '2026-01-20T00:00:00.000Z',
      '2026-02-10T00:00:00.000Z',
      '2026-03-01T00:00:00.000Z',
      '2026-03-22T00:00:00.000Z',
    ]) {
      vi.setSystemTime(new Date(timestamp))
      const refreshed = await request(app).post('/auth/refresh').set('Cookie', cookie).expect(200)
      cookie = readRefreshCookie(refreshed.headers['set-cookie'])
    }

    vi.setSystemTime(new Date('2026-04-05T00:00:00.000Z'))

    const expired = await request(app).post('/auth/refresh').set('Cookie', cookie).expect(401)

    expect(expired.body.error).toBe('Session expired. Please log in again.')
  })
})
