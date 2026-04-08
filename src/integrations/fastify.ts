import type { JwtManager } from '../core/JwtManager'
import type { AccessTokenPayload } from '../types'

export function createFastifyHandler<TPayload extends AccessTokenPayload>(
  jwt: JwtManager<TPayload>,
  type: 'authenticate' | 'refresh',
) {
  const handler = type === 'authenticate' ? jwt.authenticate() : jwt.refreshHandler()

  return async function fastifyBridge(request: { raw: unknown }, reply: { raw: unknown; send(payload: unknown): void }) {
    await handler(request.raw as never, reply.raw as never, (error: unknown) => {
      if (error) {
        reply.send(error)
      }
    })
  }
}
