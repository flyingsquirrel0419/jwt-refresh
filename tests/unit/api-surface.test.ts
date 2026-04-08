import express from 'express'
import request from 'supertest'

import { JwtManager } from '../../src'
import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'

interface TestPayload {
  userId: string
  email: string
  roles: string[]
}

describe('JwtManager direct API', () => {
  it('signs and verifies refresh tokens through the public methods', async () => {
    const jwt = new JwtManager<TestPayload>({
      access: { secret: 'access-secret', ttl: '15m' },
      refresh: { secret: 'refresh-secret', ttl: '7d', rotation: true, reuseDetection: true },
      store: new MemoryTokenStore(),
    })

    const refreshToken = await jwt.signRefreshToken('user-1', { deviceId: 'unit-test' })
    const verified = await jwt.verifyRefreshToken(refreshToken)

    expect(verified.userId).toBe('user-1')
    expect(verified.typ).toBe('refresh')
    expect(verified.jti).toEqual(expect.any(String))
  })

  it('returns json 401 responses for missing bearer tokens', async () => {
    const jwt = new JwtManager<TestPayload>({
      access: { secret: 'access-secret', ttl: '15m' },
      refresh: { secret: 'refresh-secret', ttl: '7d', rotation: true, reuseDetection: true },
      store: new MemoryTokenStore(),
    })

    const app = express()
    app.get('/protected', jwt.authenticate(), (_req, res) => {
      res.json({ ok: true })
    })

    const response = await request(app).get('/protected').expect(401)

    expect(response.body).toMatchObject({
      error: 'Missing access token',
      code: 'ACCESS_TOKEN_MISSING',
    })
  })

  it('adds an Authorization-Refreshed header when rotateOnResponse is enabled and expiry is near', async () => {
    const jwt = new JwtManager<TestPayload>({
      access: { secret: 'access-secret', ttl: '1m' },
      refresh: { secret: 'refresh-secret', ttl: '7d', rotation: true, reuseDetection: true },
      refreshBuffer: 120,
      store: new MemoryTokenStore(),
    })

    const accessToken = jwt.signAccessToken({
      userId: 'user-1',
      email: 'user@example.com',
      roles: ['member'],
    })

    const app = express()
    app.get('/protected', jwt.authenticate({ rotateOnResponse: true }), (_req, res) => {
      res.json({ ok: true })
    })

    const response = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200)

    expect(response.headers['authorization-refreshed']).toMatch(/^Bearer /)
  })
})
