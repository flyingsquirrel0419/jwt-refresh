import express from 'express'
import request from 'supertest'

import { JwtManager } from '../../src/index'
import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'

interface TestPayload {
  userId: string
  email: string
  roles: string[]
}

function extractCookie(setCookieHeader: string | string[] | undefined, name = 'refreshToken'): string {
  const values = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader ?? '']
  const match = values
    .flatMap((value) => value.split(';'))
    .map((value) => value.trim())
    .find((value) => value.startsWith(`${name}=`))

  if (!match) {
    throw new Error(`Cookie ${name} not found`)
  }

  return match
}

function createManager() {
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
    refreshBuffer: 120,
    cookie: {
      path: '/auth',
      sameSite: 'strict',
    },
    store: new MemoryTokenStore(),
  })
}

function createApp(jwt: JwtManager<TestPayload>) {
  const app = express()
  app.use(express.json())

  app.post('/auth/login', async (req, res) => {
    const { accessToken, refreshToken, sessionId } = await jwt.issueTokens(
      res,
      {
        userId: 'user-1',
        email: 'user@example.com',
        roles: ['member'],
      },
      {
        deviceId: req.headers['x-device-id'] as string | undefined,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
    )

    res.json({ accessToken, refreshToken, sessionId })
  })

  app.post('/auth/refresh', jwt.refreshHandler())

  app.get('/api/me', jwt.authenticate(), (req, res) => {
    res.json(req.user)
  })

  app.post('/auth/logout', jwt.authenticate(), async (req, res) => {
    await jwt.revokeCurrentSession(req, res)
    res.json({ ok: true })
  })

  return app
}

describe('JwtManager integration flow', () => {
  it('issues tokens, sets refresh cookie, and authenticates requests', async () => {
    const jwt = createManager()
    const app = createApp(jwt)

    const login = await request(app).post('/auth/login').expect(200)
    const cookie = extractCookie(login.headers['set-cookie'])

    expect(cookie).toContain('refreshToken=')
    expect(login.body.accessToken).toEqual(expect.any(String))
    expect(login.body.refreshToken).toEqual(expect.any(String))
    expect(login.body.sessionId).toEqual(expect.any(String))

    const me = await request(app)
      .get('/api/me')
      .set('Authorization', `Bearer ${login.body.accessToken}`)
      .expect(200)

    expect(me.body).toMatchObject({
      userId: 'user-1',
      email: 'user@example.com',
      roles: ['member'],
    })

    const sessions = await jwt.getSessions('user-1')
    expect(sessions).toHaveLength(1)
    expect(sessions[0]).toMatchObject({
      userId: 'user-1',
      deviceId: undefined,
      revokedAt: undefined,
    })
  })

  it('rotates refresh tokens and invalidates the old session on refresh', async () => {
    const jwt = createManager()
    const app = createApp(jwt)

    const login = await request(app).post('/auth/login').expect(200)
    const originalRefreshCookie = extractCookie(login.headers['set-cookie'])

    const refreshed = await request(app)
      .post('/auth/refresh')
      .set('Cookie', originalRefreshCookie)
      .expect(200)

    const rotatedCookie = extractCookie(refreshed.headers['set-cookie'])

    expect(rotatedCookie).not.toEqual(originalRefreshCookie)
    expect(refreshed.body.accessToken).toEqual(expect.any(String))
    expect(refreshed.body.sessionId).toEqual(expect.any(String))

    const sessions = await jwt.getSessions('user-1')
    expect(sessions).toHaveLength(2)

    const revoked = sessions.find((session) => session.revokedReason === 'rotation')
    const active = sessions.find((session) => !session.revokedAt)

    expect(revoked?.revokedAt).toBeInstanceOf(Date)
    expect(active?.revokedAt).toBeUndefined()
  })

  it('blacklists an access token and rejects it immediately', async () => {
    const jwt = createManager()
    const app = createApp(jwt)

    const login = await request(app).post('/auth/login').expect(200)

    await jwt.blacklistToken(login.body.accessToken, {
      reason: 'password_changed',
      userId: 'user-1',
    })

    const denied = await request(app)
      .get('/api/me')
      .set('Authorization', `Bearer ${login.body.accessToken}`)
      .expect(401)

    expect(denied.body.error).toBe('Token has been revoked')
  })

  it('revokeCurrentSession clears the current refresh session', async () => {
    const jwt = createManager()
    const app = createApp(jwt)

    const login = await request(app).post('/auth/login').expect(200)
    const currentCookie = extractCookie(login.headers['set-cookie'])

    await request(app)
      .post('/auth/logout')
      .set('Cookie', currentCookie)
      .set('Authorization', `Bearer ${login.body.accessToken}`)
      .expect(200)

    const refreshAfterLogout = await request(app)
      .post('/auth/refresh')
      .set('Cookie', currentCookie)
      .expect(401)

    expect(refreshAfterLogout.body.error).toBe('Refresh token is no longer valid')
  })
})
