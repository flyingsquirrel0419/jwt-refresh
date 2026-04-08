import type { JwtManager } from '../core/JwtManager'
import type { AccessTokenPayload } from '../types'

export function createNestGuard<TPayload extends AccessTokenPayload>(jwt: JwtManager<TPayload>) {
  return {
    canActivate: async (context: {
      switchToHttp(): { getRequest(): unknown; getResponse(): unknown }
    }) => {
      const http = context.switchToHttp()
      await jwt.authenticate()(http.getRequest() as never, http.getResponse() as never)
      return true
    },
  }
}

export function getJwtUser<TPayload extends AccessTokenPayload>(request: { user?: TPayload }): TPayload | undefined {
  return request.user
}
