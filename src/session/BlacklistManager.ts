import { JwtRefreshError } from '../errors'
import type { AccessTokenPayload, BlacklistRecord, TokenStore } from '../types'

export class BlacklistManager<TPayload extends AccessTokenPayload> {
  constructor(private readonly store: TokenStore<TPayload>) {}

  async blacklist(record: BlacklistRecord): Promise<void> {
    if (record.expiresAt.getTime() <= Date.now()) {
      throw new JwtRefreshError('Cannot blacklist an expired access token', 400, 'TOKEN_ALREADY_EXPIRED')
    }

    await this.store.blacklistToken(record)
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    return this.store.isBlacklisted(jti)
  }
}
