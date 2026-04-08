import type { MutexAdapter } from '../types'

interface RedlockLike {
  acquire(resources: string[], ttl: number): Promise<{ release(): Promise<void> }>
}

interface RedlockMutexOptions {
  lockTtl?: number
}

export class RedlockMutex implements MutexAdapter {
  constructor(
    private readonly redlock: RedlockLike,
    private readonly options: RedlockMutexOptions = {},
  ) {}

  async acquire(key: string): Promise<() => void> {
    const lock = await this.redlock.acquire([key], this.options.lockTtl ?? 2_000)
    return () => {
      void lock.release()
    }
  }
}
