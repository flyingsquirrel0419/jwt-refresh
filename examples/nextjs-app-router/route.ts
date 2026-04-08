import { JwtManager, MemoryTokenStore } from '../../src'

const jwt = new JwtManager({
  access: { secret: process.env.JWT_SECRET ?? 'access-secret', ttl: '15m' },
  refresh: {
    secret: process.env.REFRESH_SECRET ?? 'refresh-secret',
    ttl: '7d',
    rotation: true,
    reuseDetection: true,
  },
  store: new MemoryTokenStore(),
})

export async function POST(request: Request) {
  const response = new Headers()
  const res = {
    setHeader(name: string, value: string | string[]) {
      for (const item of Array.isArray(value) ? value : [value]) {
        response.append(name, item)
      }
    },
    getHeader(name: string) {
      return response.get(name) ?? undefined
    },
  }

  await jwt.issueTokens(
    res,
    {
      userId: 'user-1',
      email: 'user@example.com',
      roles: ['member'],
    },
    {
      userAgent: request.headers.get('user-agent') ?? undefined,
    },
  )

  return new Response(JSON.stringify({ ok: true }), { headers: response })
}
