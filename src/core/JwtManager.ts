import { EventEmitter } from 'node:events'

import { JwtRefreshError } from '../errors'
import { InMemoryMutex } from '../mutex/InMemoryMutex'
import { createAuthenticateHandler } from '../middleware/authenticate'
import { createRefreshHandler } from '../middleware/refreshHandler'
import { RotationEngine } from '../rotation/RotationEngine'
import { BlacklistManager } from '../session/BlacklistManager'
import { SessionManager } from '../session/SessionManager'
import type {
  AccessTokenPayload,
  AuthenticateOptions,
  JwtManagerOptions,
  RefreshHandlerOptions,
  RequestHandler,
  RequestLike,
  ResponseLike,
  SessionMeta,
  TokenIssueResult,
  TypedEventEmitter,
  VerifiedRefreshPayload,
} from '../types'
import {
  clearCookie,
  createTokenId,
  defaultCookieOptions,
  getRefreshTokenFromRequest,
  hashToken,
  normalizeAccessPayload,
  setCookie,
} from '../utils'
import { RefreshCoordinator } from './RefreshCoordinator'
import { TokenIssuer } from './TokenIssuer'
import { TokenVerifier } from './TokenVerifier'

type MutableOptions<TPayload extends AccessTokenPayload> = JwtManagerOptions<TPayload> & {
  emit: TypedEventEmitter<TPayload>['emit']
}

export class JwtManager<TPayload extends AccessTokenPayload = AccessTokenPayload>
  extends EventEmitter
  implements TypedEventEmitter<TPayload>
{
  private readonly options: MutableOptions<TPayload>
  private readonly issuer: TokenIssuer<TPayload>
  private readonly verifier: TokenVerifier<TPayload>
  private readonly refreshCoordinator: RefreshCoordinator<TPayload>
  private readonly sessionManager: SessionManager<TPayload>
  private readonly blacklistManager: BlacklistManager<TPayload>

  constructor(options: JwtManagerOptions<TPayload>) {
    super()

    const mutex =
      options.mutex && typeof options.mutex !== 'string'
        ? options.mutex
        : new InMemoryMutex()

    this.options = {
      ...options,
      mutex,
      emit: this.emit.bind(this) as TypedEventEmitter<TPayload>['emit'],
    }

    this.issuer = new TokenIssuer(this.options)
    this.verifier = new TokenVerifier(this.options)
    this.refreshCoordinator = new RefreshCoordinator(this.options, new RotationEngine(this.options, this.issuer))
    this.sessionManager = new SessionManager(this.options.store)
    this.blacklistManager = new BlacklistManager(this.options.store)
  }

  async issueTokens(
    res: ResponseLike,
    payload: TPayload,
    sessionMeta: SessionMeta = {},
  ): Promise<TokenIssueResult> {
    const sessionId = createTokenId()
    const refreshToken = this.issuer.issueRefreshToken(payload.userId, sessionId)
    const accessToken = this.issuer.issueAccessToken(payload, sessionId)
    const session = this.issuer.createSessionRecord(sessionId, payload, refreshToken, sessionMeta)

    await this.callStore(() => this.options.store.createSession(session))

    const cookieOptions = defaultCookieOptions(this.options.refresh.ttl, this.options.cookie)
    setCookie(res, cookieOptions.name, refreshToken.token, cookieOptions)

    const result = {
      accessToken: accessToken.token,
      refreshToken: refreshToken.token,
      sessionId,
    }
    this.emit('token:issued', { ...result, payload })
    return result
  }

  signAccessToken(payload: TPayload): string {
    return this.issuer.issueAccessToken(payload).token
  }

  async signRefreshToken(userId: string, sessionMeta: SessionMeta = {}): Promise<string> {
    const sessionId = createTokenId()
    const refreshToken = this.issuer.issueRefreshToken(userId, sessionId)
    await this.callStore(() =>
      this.options.store.createSession({
        tokenId: sessionId,
        userId,
        tokenHash: refreshToken.session.tokenHash,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        expiresAt: refreshToken.session.expiresAt,
        originalCreatedAt: refreshToken.session.originalCreatedAt,
        metadata: { ...sessionMeta },
      }),
    )
    return refreshToken.token
  }

  verifyAccessToken(token: string): TPayload {
    const payload = this.verifier.verifyAccessToken(token)
    return normalizeAccessPayload(payload)
  }

  async verifyRefreshToken(token: string): Promise<VerifiedRefreshPayload> {
    const payload = this.verifier.verifyRefreshToken(token)
    const session = await this.callStore(() => this.options.store.getSession(payload.jti))
    if (!session || session.tokenHash !== hashToken(token)) {
      throw new JwtRefreshError('Refresh token is no longer valid', 401, 'SESSION_NOT_FOUND')
    }
    return payload
  }

  authenticate(options: AuthenticateOptions = {}): RequestHandler {
    return createAuthenticateHandler(this, options)
  }

  refreshHandler(options: RefreshHandlerOptions = {}): RequestHandler {
    return createRefreshHandler(this, options)
  }

  async refreshToken(refreshToken: string, req: RequestLike): Promise<ReturnType<RefreshCoordinator<TPayload>['refresh']>> {
    const verified = this.verifier.verifyRefreshToken(refreshToken)
    return this.refreshCoordinator.refresh(verified, refreshToken, req)
  }

  async revokeCurrentSession(req: RequestLike, res: ResponseLike): Promise<void> {
    const sessionId = req.auth?.sessionId
    const userId = req.auth?.userId

    if (sessionId && userId) {
      await this.callStore(() => this.sessionManager.revokeSession(userId, sessionId, 'logout'))
      this.emit('token:revoked', {
        tokenId: sessionId,
        userId,
        reason: 'logout',
        revokedAt: new Date(),
      })
    }

    const cookieOptions = defaultCookieOptions(this.options.refresh.ttl, this.options.cookie)
    clearCookie(res, cookieOptions.name, cookieOptions)
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    await this.callStore(() => this.sessionManager.revokeSession(userId, sessionId, 'manual'))
    this.emit('token:revoked', {
      tokenId: sessionId,
      userId,
      reason: 'manual',
      revokedAt: new Date(),
    })
  }

  async revokeAllSessions(userId: string): Promise<void> {
    const sessions = await this.getSessions(userId)
    await this.callStore(() => this.sessionManager.revokeAllSessions(userId, 'manual'))
    for (const session of sessions) {
      this.emit('token:revoked', {
        tokenId: session.sessionId,
        userId,
        reason: 'manual',
        revokedAt: new Date(),
      })
    }
  }

  async getSessions(userId: string, currentSessionId?: string) {
    return this.callStore(() => this.sessionManager.getSessions(userId, currentSessionId))
  }

  async blacklistToken(token: string, options: { reason?: string; userId?: string } = {}): Promise<void> {
    const payload = this.verifier.verifyAccessToken(token)
    const exp = payload.exp
    if (!exp) {
      throw new JwtRefreshError('Access token is missing an expiration', 400, 'ACCESS_TOKEN_EXP_MISSING')
    }

    await this.callStore(() =>
      this.blacklistManager.blacklist({
        jti: payload.jti,
        expiresAt: new Date(exp * 1000),
        reason: options.reason,
        userId: options.userId ?? payload.userId,
      }),
    )
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    return this.callStore(() => this.blacklistManager.isBlacklisted(jti))
  }

  getCookieOptions() {
    return defaultCookieOptions(this.options.refresh.ttl, this.options.cookie)
  }

  getRefreshBuffer(): number {
    return this.options.refreshBuffer ?? 0
  }

  getRefreshCookie(req: RequestLike): string | null {
    const cookieOptions = this.getCookieOptions()
    return getRefreshTokenFromRequest(req, cookieOptions.name)
  }

  getTokenVerifier(): TokenVerifier<TPayload> {
    return this.verifier
  }

  private async callStore<TResult>(operation: () => Promise<TResult>): Promise<TResult> {
    try {
      return await operation()
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error))
      this.emit('store:error', normalized)
      if ((this.options.onStoreError ?? 'warn') === 'throw') {
        throw normalized
      }
      return Promise.reject(normalized)
    }
  }
}
