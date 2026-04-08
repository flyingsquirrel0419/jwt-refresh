import express from 'express'
import { JwtManager, MemoryTokenStore } from '../../src'

const app = express()
app.use(express.json())

const jwt = new JwtManager({
  access: { secret: 'access-secret', ttl: '15m' },
  refresh: {
    secret: 'refresh-secret',
    ttl: '7d',
    rotation: true,
    reuseDetection: true,
    absoluteExpiry: '90d',
  },
  cookie: {
    name: 'refreshToken',
    httpOnly: true,
    path: '/auth',
    sameSite: 'strict',
  },
  store: new MemoryTokenStore(),
})

app.post('/auth/login', async (_req, res) => {
  const { accessToken } = await jwt.issueTokens(res, {
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['member'],
  })

  res.json({ accessToken })
})

app.post('/auth/refresh', jwt.refreshHandler())
app.get('/api/me', jwt.authenticate(), (req, res) => res.json(req.user))

app.listen(3000, () => {
  console.log('Example server listening on http://localhost:3000')
})
