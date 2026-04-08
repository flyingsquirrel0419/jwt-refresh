import { sign } from 'jsonwebtoken'

import { JwtRefreshError } from '../../src/errors'
import { createFastifyHandler } from '../../src/integrations/fastify'
import { createNestGuard, getJwtUser } from '../../src/integrations/nestjs'
import { createNextRefreshHandler, verifyNextRequest } from '../../src/integrations/nextjs'
import {
  addMilliseconds,
  clearCookie,
  defaultCookieOptions,
  extractBearerToken,
  getRefreshTokenFromRequest,
  hashToken,
  jsonResponse,
  normalizeRefreshPayload,
  parseRequestCookies,
  setCookie,
  ttlToMilliseconds,
  ttlToSeconds,
  verifyJwt,
} from '../../src/utils'
import { JwtManager } from '../../src'
import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'

interface TestPayload {
  userId: string
  email: string
  roles: string[]
}

describe('utils and integration helpers', () => {
  it('parses ttl values and throws for invalid ones', () => {
    expect(ttlToMilliseconds(5)).toBe(5000)
    expect(ttlToSeconds('1500ms')).toBe(1)
    expect(addMilliseconds(new Date('2026-01-01T00:00:00.000Z'), 1000).toISOString()).toBe('2026-01-01T00:00:01.000Z')
    expect(() => ttlToMilliseconds('nope' as never)).toThrow(JwtRefreshError)
  })

  it('parses bearer tokens and cookies from headers', () => {
    expect(
      extractBearerToken({
        headers: { authorization: 'Bearer token-1' },
      }),
    ).toBe('token-1')
    expect(extractBearerToken({ headers: { authorization: 'Basic token-1' } })).toBeNull()
    expect(parseRequestCookies({ headers: { cookie: 'a=1; refreshToken=abc' } })).toMatchObject({
      a: '1',
      refreshToken: 'abc',
    })
    expect(getRefreshTokenFromRequest({ headers: { cookie: 'refreshToken=abc' } }, 'refreshToken')).toBe('abc')
  })

  it('supports raw response objects for setCookie, clearCookie, and jsonResponse', () => {
    const headers = new Map<string, string | string[]>()
    const response = {
      setHeader(name: string, value: string | string[]) {
        headers.set(name, value)
      },
      getHeader(name: string) {
        return headers.get(name)
      },
    }
    const options = defaultCookieOptions('15m', { domain: 'example.com', secure: true })

    setCookie(response, 'refreshToken', 'abc', options)
    clearCookie(response, 'refreshToken', options)
    const body = jsonResponse(response, 200, { ok: true })

    const setCookieHeader = headers.get('Set-Cookie')
    expect(Array.isArray(setCookieHeader)).toBe(true)
    expect(String((setCookieHeader as string[])[0])).toContain('Domain=example.com')
    expect(String((setCookieHeader as string[])[1])).toContain('Max-Age=0')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(body).toEqual({ ok: true })
  })

  it('verifies JWTs across legacy secrets and rejects malformed refresh payloads', () => {
    const token = sign({ userId: 'user-1', typ: 'refresh', jti: 'token-1' }, 'legacy-secret', { expiresIn: '1h' })
    expect(verifyJwt(token, ['wrong-secret', 'legacy-secret'], {})).toMatchObject({ userId: 'user-1' })
    expect(() => normalizeRefreshPayload({ userId: 'user-1', typ: 'refresh' })).toThrow(JwtRefreshError)
    expect(hashToken('abc')).toHaveLength(64)
  })

  it('supports nextjs, fastify, and nestjs helper adapters', async () => {
    const jwt = new JwtManager<TestPayload>({
      access: { secret: 'access-secret', ttl: '15m' },
      refresh: { secret: 'refresh-secret', ttl: '7d', rotation: true, reuseDetection: true },
      store: new MemoryTokenStore(),
    })

    const accessToken = jwt.signAccessToken({
      userId: 'user-1',
      email: 'user@example.com',
      roles: ['member'],
    })

    await expect(verifyNextRequest(jwt, new Request('http://localhost'))).rejects.toThrow('Missing access token')
    await expect(
      verifyNextRequest(
        jwt,
        new Request('http://localhost', {
          headers: { authorization: `Bearer ${accessToken}` },
        }),
      ),
    ).resolves.toMatchObject({ userId: 'user-1' })

    const issueHeaders = new Headers()
    const res = {
      setHeader(name: string, value: string | string[]) {
        for (const item of Array.isArray(value) ? value : [value]) {
          issueHeaders.append(name, item)
        }
      },
      getHeader(name: string) {
        return issueHeaders.get(name) ?? undefined
      },
    }
    await jwt.issueTokens(
      res,
      { userId: 'user-1', email: 'user@example.com', roles: ['member'] },
      { deviceId: 'next' },
    )
    const cookieHeader = issueHeaders.get('Set-Cookie')
    const refreshHandler = createNextRefreshHandler(jwt)
    const nextResponse = await refreshHandler(
      new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { cookie: cookieHeader ?? '' },
      }),
    )
    expect(nextResponse.headers.get('set-cookie')).toContain('refreshToken=')

    const authenticate = vi.fn(async (_req: unknown, _res: unknown, next?: (error?: unknown) => void) => next?.())
    const refresh = vi.fn(async (_req: unknown, _res: unknown, next?: (error?: unknown) => void) => next?.(new Error('boom')))
    const fastifyJwt = {
      authenticate: () => authenticate,
      refreshHandler: () => refresh,
    } as unknown as JwtManager<TestPayload>
    const reply = { raw: {}, send: vi.fn() }

    await createFastifyHandler(fastifyJwt, 'authenticate')({ raw: {} }, reply)
    await createFastifyHandler(fastifyJwt, 'refresh')({ raw: {} }, reply)
    expect(authenticate).toHaveBeenCalled()
    expect(reply.send).toHaveBeenCalled()

    const nestAuthenticate = vi.fn(async () => undefined)
    const guard = createNestGuard({
      authenticate: () => nestAuthenticate,
    } as unknown as JwtManager<TestPayload>)
    await expect(
      guard.canActivate({
        switchToHttp: () => ({
          getRequest: () => ({}),
          getResponse: () => ({}),
        }),
      }),
    ).resolves.toBe(true)
    expect(getJwtUser({ user: { userId: 'user-1', email: 'a', roles: [] } })).toMatchObject({ userId: 'user-1' })
  })
})
