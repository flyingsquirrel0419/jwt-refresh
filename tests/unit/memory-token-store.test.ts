import { MemoryTokenStore } from '../../src/stores/MemoryTokenStore'

describe('MemoryTokenStore', () => {
  it('removes expired sessions and blacklist entries during cleanup', async () => {
    const store = new MemoryTokenStore()
    const past = new Date(Date.now() - 60_000)

    await store.createSession({
      tokenId: 'expired-session',
      userId: 'user-1',
      tokenHash: 'hash',
      createdAt: past,
      lastUsedAt: past,
      expiresAt: past,
    })

    await store.blacklistToken({
      jti: 'expired-jti',
      expiresAt: past,
    })

    await store.cleanup()

    expect(await store.getSession('expired-session')).toBeNull()
    expect(await store.isBlacklisted('expired-jti')).toBe(false)
  })

  it('revokes all sessions for a user', async () => {
    const store = new MemoryTokenStore()
    const future = new Date(Date.now() + 60_000)

    await store.createSession({
      tokenId: 's1',
      userId: 'user-1',
      tokenHash: 'hash-1',
      createdAt: new Date(),
      lastUsedAt: new Date(),
      expiresAt: future,
    })

    await store.createSession({
      tokenId: 's2',
      userId: 'user-1',
      tokenHash: 'hash-2',
      createdAt: new Date(),
      lastUsedAt: new Date(),
      expiresAt: future,
    })

    await store.revokeAllByUserId('user-1', 'manual')

    const sessions = await store.getSessionsByUserId('user-1')
    expect(sessions).toHaveLength(2)
    expect(sessions.every((session) => session.revokedReason === 'manual')).toBe(true)
  })
})
