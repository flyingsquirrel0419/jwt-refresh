import { sign } from 'jsonwebtoken'

import { JwtRefreshError } from '../../src/errors'
import { JwtManager } from '../../src'
import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'
import {
  clearCookie,
  defaultCookieOptions,
  extractBearerToken,
  jsonResponse,
  normalizeRefreshPayload,
  parseRequestCookies,
  setCookie,
  verifyJwt,
} from '../../src/utils'
import { createNextRefreshHandler } from '../../src/integrations/nextjs'
import { JwtManager as ExpressJwtManager, MemoryTokenStore as ExpressMemoryTokenStore } from '../../src/integrations/express'

interface TestPayload {
  userId: string
  email: string
  roles: string[]
}

function createRawResponse() {
  const headers = new Map<string, string | string[]>()

  return {
    headers,
    response: {
      setHeader(name: string, value: string | string[]) {
        headers.set(name, value)
      },
      getHeader(name: string) {
        return headers.get(name)
      },
    },
  }
}

describe('utils and integration deep coverage', () => {
  it('covers header-based cookie accumulation, request parsing, and JWT fallback branches', () => {
    const { headers, response } = createRawResponse()
    const options = defaultCookieOptions('15m', {
      domain: 'example.com',
      secure: true,
    })

    setCookie(response, 'refreshToken', 'abc', options)
    expect(headers.get('Set-Cookie')).toMatchObject(expect.stringContaining('refreshToken=abc'))

    setCookie(response, 'refreshToken', 'def', options)
    expect(headers.get('Set-Cookie')).toEqual([
      expect.stringContaining('refreshToken=abc'),
      expect.stringContaining('refreshToken=def'),
    ])

    setCookie(response, 'refreshToken', 'ghi', options)
    expect(headers.get('Set-Cookie')).toEqual([
      expect.stringContaining('refreshToken=abc'),
      expect.stringContaining('refreshToken=def'),
      expect.stringContaining('refreshToken=ghi'),
    ])

    clearCookie(response, 'refreshToken', options)
    expect((headers.get('Set-Cookie') as string[]).at(-1)).toContain('Max-Age=0')

    expect(parseRequestCookies({ headers: {}, cookies: { refreshToken: 'direct-cookie', other: 'value' } })).toEqual({
      refreshToken: 'direct-cookie',
      other: 'value',
    })
    expect(parseRequestCookies({ headers: {} })).toEqual({})
    expect(extractBearerToken({ headers: { authorization: ['Bearer token-from-array'] } })).toBe('token-from-array')

    const token = sign({ userId: 'user-1', typ: 'refresh', jti: 'refresh-1' }, 'secret', { expiresIn: '1h' })
    expect(verifyJwt(token, ['wrong-secret', 'secret'], {})).toMatchObject({
      userId: 'user-1',
      jti: 'refresh-1',
    })
    expect(() => verifyJwt(token, ['wrong-secret'], {})).toThrow()
    expect(() => verifyJwt(token, [], {})).toThrow(JwtRefreshError)
  })

  it('covers jsonResponse fallbacks and refresh payload normalization branches', () => {
    const statusJson = vi.fn().mockReturnValue({ json: vi.fn().mockReturnValue('json-body') })
    const statusSend = vi.fn().mockReturnValue({ send: vi.fn().mockReturnValue('send-body') })

    expect(
      jsonResponse(
        {
          status: statusJson,
          setHeader: vi.fn(),
        },
        201,
        { ok: true },
      ),
    ).toBe('json-body')

    expect(
      jsonResponse(
        {
          status: statusSend,
          setHeader: vi.fn(),
        },
        202,
        { ok: true },
      ),
    ).toBe('send-body')

    expect(
      normalizeRefreshPayload({
        userId: 'user-1',
        jti: 'refresh-1',
        typ: 'refresh',
      }),
    ).toMatchObject({
      userId: 'user-1',
      jti: 'refresh-1',
      typ: 'refresh',
    })

    expect(() => normalizeRefreshPayload({ userId: 'user-1', jti: 'refresh-1', typ: 'access' })).toThrow(
      JwtRefreshError,
    )
  })

  it('imports the express integration export surface and exercises nextjs response array handling', async () => {
    expect(ExpressJwtManager).toBe(JwtManager)
    expect(ExpressMemoryTokenStore).toBe(MemoryTokenStore)

    const refreshHandler = vi.fn(async (_req: unknown, res: { setHeader(name: string, value: string | string[]): void }) => {
      res.setHeader('Set-Cookie', ['refreshToken=one', 'refreshToken=two'])
      return undefined
    })

    const jwt = {
      refreshHandler: () => refreshHandler,
    } as unknown as JwtManager<TestPayload>

    const handler = createNextRefreshHandler(jwt)
    const response = await handler(new Request('http://localhost/auth/refresh', { method: 'POST' }))

    expect(refreshHandler).toHaveBeenCalled()
    expect(await response.text()).toBe('{}')
    expect(response.headers.get('set-cookie')).toContain('refreshToken=one')
    expect(response.headers.get('set-cookie')).toContain('refreshToken=two')
  })
})
