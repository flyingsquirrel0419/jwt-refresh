import type { JwtManager } from '../core/JwtManager'
import { JwtRefreshError } from '../errors'
import type { AccessTokenPayload } from '../types'

export async function verifyNextRequest<TPayload extends AccessTokenPayload>(
  jwt: JwtManager<TPayload>,
  request: Request,
): Promise<TPayload> {
  const authorization = request.headers.get('authorization')
  if (!authorization?.startsWith('Bearer ')) {
    throw new JwtRefreshError('Missing access token', 401, 'ACCESS_TOKEN_MISSING')
  }

  return jwt.verifyAccessToken(authorization.slice('Bearer '.length))
}

export function createNextRefreshHandler<TPayload extends AccessTokenPayload>(jwt: JwtManager<TPayload>) {
  return async function nextRefresh(request: Request): Promise<Response> {
    const responseHeaders = new Headers()
    const req = {
      headers: Object.fromEntries(request.headers.entries()),
    }
    const res = {
      setHeader(name: string, value: string | string[]) {
        const values = Array.isArray(value) ? value : [value]
        for (const item of values) {
          responseHeaders.append(name, item)
        }
      },
      getHeader(name: string) {
        return responseHeaders.get(name) ?? undefined
      },
    }

    const result = await jwt.refreshHandler()(req, res)
    return new Response(JSON.stringify(result ?? {}), { headers: responseHeaders })
  }
}
