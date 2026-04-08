import { createHash, randomUUID } from 'node:crypto'

import { parse as parseCookie } from 'cookie'
import ms from 'ms'
import type { JwtPayload, Secret, SignOptions, VerifyOptions } from 'jsonwebtoken'
import { sign, verify } from 'jsonwebtoken'

import { JwtRefreshError } from './errors'
import type {
  AccessTokenPayload,
  CookieOptions,
  RefreshTokenSession,
  RequestLike,
  ResponseLike,
  VerifiedAccessPayload,
  VerifiedRefreshPayload,
} from './types'

export function createTokenId(): string {
  return randomUUID()
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export function ttlToMilliseconds(ttl: string | number): number {
  if (typeof ttl === 'number') {
    return ttl * 1000
  }

  const parsed = ms(ttl as ms.StringValue)
  if (typeof parsed !== 'number') {
    throw new JwtRefreshError(`Invalid TTL value: ${ttl}`, 500, 'INVALID_TTL')
  }
  return parsed
}

export function ttlToSeconds(ttl: string | number): number {
  return Math.floor(ttlToMilliseconds(ttl) / 1000)
}

export function addMilliseconds(date: Date, amount: number): Date {
  return new Date(date.getTime() + amount)
}

export function extractBearerToken(req: RequestLike): string | null {
  const header = req.headers.authorization
  if (!header) {
    return null
  }

  const value = Array.isArray(header) ? header[0] : header
  if (!value?.startsWith('Bearer ')) {
    return null
  }

  return value.slice('Bearer '.length).trim()
}

export function parseRequestCookies(req: RequestLike): Record<string, string> {
  if (req.cookies) {
    return req.cookies
  }

  const header = req.headers.cookie
  if (!header) {
    return {}
  }

  const parsed = parseCookie(Array.isArray(header) ? header.join('; ') : header)
  return Object.fromEntries(
    Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  )
}

export function getRefreshTokenFromRequest(req: RequestLike, cookieName: string): string | null {
  const cookies = parseRequestCookies(req)
  return cookies[cookieName] ?? null
}

export function defaultCookieOptions(ttl: string | number, overrides: CookieOptions = {}): Required<CookieOptions> {
  return {
    name: overrides.name ?? 'refreshToken',
    httpOnly: overrides.httpOnly ?? true,
    secure: overrides.secure ?? process.env.NODE_ENV === 'production',
    sameSite: overrides.sameSite ?? 'strict',
    domain: overrides.domain ?? '',
    path: overrides.path ?? '/',
    maxAge: overrides.maxAge ?? ttlToSeconds(ttl),
  }
}

function serializeCookie(name: string, value: string, options: Required<CookieOptions>): string {
  const parts = [`${name}=${value}`]
  parts.push(`Max-Age=${options.maxAge}`)
  parts.push(`Path=${options.path}`)

  if (options.domain) {
    parts.push(`Domain=${options.domain}`)
  }
  if (options.httpOnly) {
    parts.push('HttpOnly')
  }
  if (options.secure) {
    parts.push('Secure')
  }
  if (options.sameSite) {
    const sameSite = options.sameSite
    parts.push(`SameSite=${sameSite.charAt(0).toUpperCase()}${sameSite.slice(1)}`)
  }

  return parts.join('; ')
}

export function setCookie(res: ResponseLike, name: string, value: string, options: Required<CookieOptions>): void {
  if (typeof res.cookie === 'function') {
    res.cookie(name, value, {
      httpOnly: options.httpOnly,
      secure: options.secure,
      sameSite: options.sameSite,
      domain: options.domain || undefined,
      path: options.path,
      maxAge: options.maxAge * 1000,
    })
    return
  }

  const serialized = serializeCookie(name, value, options)
  const existing = res.getHeader?.('Set-Cookie')
  if (!existing) {
    res.setHeader('Set-Cookie', serialized)
    return
  }

  const cookies = Array.isArray(existing) ? [...existing, serialized] : [String(existing), serialized]
  res.setHeader('Set-Cookie', cookies)
}

export function clearCookie(res: ResponseLike, name: string, options: Required<CookieOptions>): void {
  if (typeof res.clearCookie === 'function') {
    res.clearCookie(name, {
      httpOnly: options.httpOnly,
      secure: options.secure,
      sameSite: options.sameSite,
      domain: options.domain || undefined,
      path: options.path,
    })
    return
  }

  setCookie(res, name, '', { ...options, maxAge: 0 })
}

export function jsonResponse(res: ResponseLike, status: number, body: unknown): unknown {
  const target = typeof res.status === 'function' ? res.status(status) : res
  if (typeof target.json === 'function') {
    return target.json(body)
  }
  if (typeof target.send === 'function') {
    return target.send(body)
  }
  res.setHeader('Content-Type', 'application/json')
  return body
}

export function signJwt<TPayload extends JwtPayload>(
  payload: TPayload,
  secret: Secret,
  options: SignOptions,
): string {
  return sign(payload, secret, options)
}

export function verifyJwt<TPayload extends JwtPayload>(
  token: string,
  secrets: Secret[],
  options: VerifyOptions,
): TPayload {
  let lastError: unknown

  for (const secret of secrets) {
    try {
      return verify(token, secret, options) as TPayload
    } catch (error) {
      lastError = error
    }
  }

  if (lastError instanceof Error) {
    throw lastError
  }

  throw new JwtRefreshError('Token verification failed', 401, 'TOKEN_INVALID')
}

export function isSessionExpired<TPayload extends AccessTokenPayload>(
  session: RefreshTokenSession<TPayload>,
  now = new Date(),
): boolean {
  return session.expiresAt.getTime() <= now.getTime()
}

export function normalizeAccessPayload<TPayload extends AccessTokenPayload>(
  payload: VerifiedAccessPayload<TPayload>,
): TPayload {
  const { iat: _iat, exp: _exp, nbf: _nbf, iss: _iss, aud: _aud, sub: _sub, jti: _jti, sid: _sid, typ: _typ, ...rest } =
    payload
  return rest as TPayload
}

export function normalizeRefreshPayload(payload: JwtPayload): VerifiedRefreshPayload {
  if (typeof payload.userId !== 'string' || typeof payload.jti !== 'string' || payload.typ !== 'refresh') {
    throw new JwtRefreshError('Refresh token payload is malformed', 401, 'REFRESH_TOKEN_INVALID')
  }

  return payload as VerifiedRefreshPayload
}
