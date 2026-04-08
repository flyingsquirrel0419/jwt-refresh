import type { EventEmitter } from 'node:events'
import 'express-serve-static-core'
import type { Algorithm, JwtPayload, Secret } from 'jsonwebtoken'

export interface AccessTokenPayload {
  userId: string
}

export interface SessionMeta extends Record<string, unknown> {
  deviceId?: string
  userAgent?: string
  ip?: string
}

export interface TokenIssueResult {
  accessToken: string
  refreshToken: string
  sessionId: string
}

export interface CookieOptions {
  name?: string
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'strict' | 'lax' | 'none'
  domain?: string
  path?: string
  maxAge?: number
}

export interface JwtTokenOptions {
  secret: Secret
  ttl: string | number
  algorithm?: Algorithm
  issuer?: string
  audience?: string | string[]
  legacySecrets?: Secret[]
}

export interface RefreshTokenOptions extends JwtTokenOptions {
  rotation?: boolean
  reuseDetection?: boolean
  absoluteExpiry?: string | number
}

export interface MutexAdapter {
  acquire(key: string): Promise<() => void>
  isLocked?(key: string): boolean
}

export interface JwtManagerOptions<TPayload extends AccessTokenPayload> {
  access: JwtTokenOptions
  refresh: RefreshTokenOptions
  store: TokenStore<TPayload>
  mutex?: 'memory' | MutexAdapter
  cookie?: CookieOptions
  refreshBuffer?: number
  onStoreError?: 'throw' | 'warn'
  extractContext?: (req: RequestLike) => Record<string, unknown>
}

export interface RefreshTokenSession<TPayload extends AccessTokenPayload = AccessTokenPayload> {
  tokenId: string
  userId: string
  tokenHash: string
  deviceId?: string
  userAgent?: string
  ip?: string
  createdAt: Date
  lastUsedAt: Date
  expiresAt: Date
  revokedAt?: Date
  revokedReason?: RevokedReason
  parentTokenId?: string
  metadata?: Record<string, unknown>
  accessPayload?: TPayload
  originalCreatedAt?: Date
}

export interface SessionInfo {
  sessionId: string
  userId: string
  deviceId?: string
  userAgent?: string
  ip?: string
  createdAt: Date
  lastUsedAt: Date
  expiresAt: Date
  revokedAt?: Date
  revokedReason?: RevokedReason
  isCurrent: boolean
}

export interface BlacklistRecord {
  jti: string
  expiresAt: Date
  reason?: string
  userId?: string
}

export interface TokenStore<TPayload extends AccessTokenPayload = AccessTokenPayload> {
  createSession(session: RefreshTokenSession<TPayload>): Promise<void>
  getSession(tokenId: string): Promise<RefreshTokenSession<TPayload> | null>
  revokeSession(tokenId: string, reason?: RevokedReason): Promise<void>
  revokeAllByUserId(userId: string, reason?: RevokedReason): Promise<void>
  getSessionsByUserId(userId: string): Promise<Array<RefreshTokenSession<TPayload>>>
  touchSession(tokenId: string, touchedAt?: Date): Promise<void>
  blacklistToken(record: BlacklistRecord): Promise<void>
  isBlacklisted(jti: string): Promise<boolean>
  cleanup?(): Promise<void>
}

export interface AuthenticateOptions {
  rotateOnResponse?: boolean
}

export interface RefreshHandlerOptions {
  cookieName?: string
}

export interface RequestLike {
  headers: Record<string, string | string[] | undefined>
  cookies?: Record<string, string>
  user?: unknown
  auth?: AuthContext
  ip?: string
  method?: string
  path?: string
}

export interface ResponseLike {
  setHeader(name: string, value: number | string | string[]): void
  getHeader?(name: string): number | string | string[] | undefined
  status?(code: number): ResponseLike
  json?(body: unknown): unknown
  send?(body: unknown): unknown
  cookie?(name: string, value: string, options?: Record<string, unknown>): void
  clearCookie?(name: string, options?: Record<string, unknown>): void
}

export type NextFunction = (error?: unknown) => void
export type RequestHandler = (req: any, res: any, next?: any) => unknown

export type VerifiedAccessPayload<TPayload extends AccessTokenPayload> = JwtPayload &
  TPayload & {
    jti: string
    sid?: string
    typ: 'access'
  }

export interface VerifiedRefreshPayload extends JwtPayload {
  userId: string
  jti: string
  typ: 'refresh'
}

export interface AuthContext {
  sessionId?: string
  tokenId: string
  userId: string
}

export type RevokedReason =
  | 'logout'
  | 'rotation'
  | 'reuse_detected'
  | 'password_changed'
  | 'absolute_expired'
  | 'manual'

export interface RefreshSuccessResult<TPayload extends AccessTokenPayload> {
  type: 'success'
  accessToken: string
  refreshToken: string
  sessionId: string
  payload: TPayload
}

export interface RefreshRetryResult {
  type: 'retry'
}

export type RefreshResult<TPayload extends AccessTokenPayload> = RefreshSuccessResult<TPayload> | RefreshRetryResult

export interface TokenReuseEvent {
  userId: string
  tokenId: string
  detectedAt: Date
  ip?: string
  userAgent?: string
}

export interface TokenRefreshEvent {
  userId: string
  oldTokenId: string
  newTokenId: string
  refreshedAt: Date
}

export interface TokenRevokedEvent {
  userId: string
  tokenId: string
  reason: RevokedReason
  revokedAt: Date
}

export interface JwtRefreshEvents<TPayload extends AccessTokenPayload> {
  'token:reuse-detected': (event: TokenReuseEvent) => void
  'token:refreshed': (event: TokenRefreshEvent) => void
  'token:revoked': (event: TokenRevokedEvent) => void
  'store:error': (error: Error) => void
  'token:issued': (event: TokenIssueResult & { payload: TPayload }) => void
}

export interface TypedEventEmitter<TPayload extends AccessTokenPayload> extends EventEmitter {
  on<EventName extends keyof JwtRefreshEvents<TPayload>>(
    eventName: EventName,
    listener: JwtRefreshEvents<TPayload>[EventName],
  ): this
  emit<EventName extends keyof JwtRefreshEvents<TPayload>>(
    eventName: EventName,
    ...args: Parameters<JwtRefreshEvents<TPayload>[EventName]>
  ): boolean
}

declare module 'express-serve-static-core' {
  interface Request {
    user?: AccessTokenPayload
    auth?: AuthContext
  }
}
