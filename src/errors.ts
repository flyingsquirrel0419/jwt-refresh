export class JwtRefreshError extends Error {
  readonly statusCode: number
  readonly code: string

  constructor(message: string, statusCode = 400, code = 'JWT_REFRESH_ERROR') {
    super(message)
    this.name = 'JwtRefreshError'
    this.statusCode = statusCode
    this.code = code
  }
}
