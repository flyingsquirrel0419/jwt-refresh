import { JwtRefreshError } from '../errors'
import type { AccessTokenPayload, RequestLike, TokenReuseEvent, TokenStore } from '../types'

export class ReuseDetector<TPayload extends AccessTokenPayload> {
  constructor(private readonly store: TokenStore<TPayload>) {}

  async handleReuse(session: { tokenId: string; userId: string }, req: RequestLike): Promise<TokenReuseEvent> {
    await this.store.revokeAllByUserId(session.userId, 'reuse_detected')

    return {
      userId: session.userId,
      tokenId: session.tokenId,
      detectedAt: new Date(),
      ip: req.ip,
      userAgent: req.headers['user-agent'] as string | undefined,
    }
  }

  fail(): never {
    throw new JwtRefreshError('Refresh token reuse detected', 401, 'REFRESH_TOKEN_REUSED')
  }
}
