import type { MutexAdapter } from '../types'

export class InMemoryMutex implements MutexAdapter {
  private readonly locks = new Map<string, Promise<void>>()

  isLocked(key: string): boolean {
    return this.locks.has(key)
  }

  async acquire(key: string): Promise<() => void> {
    while (this.locks.has(key)) {
      await this.locks.get(key)
    }

    let releaseLock!: () => void
    const lock = new Promise<void>((resolve) => {
      releaseLock = resolve
    })

    this.locks.set(key, lock)

    return () => {
      this.locks.delete(key)
      releaseLock()
    }
  }
}
