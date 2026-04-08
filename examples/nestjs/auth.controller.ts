import type { Request, Response } from 'express'
import { Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common'
import { JwtManager, MemoryTokenStore } from '../../src'

const jwt = new JwtManager({
  access: { secret: 'access-secret', ttl: '15m' },
  refresh: { secret: 'refresh-secret', ttl: '7d', rotation: true, reuseDetection: true },
  store: new MemoryTokenStore(),
})

@Controller('auth')
export class AuthController {
  @Post('login')
  async login(@Res() res: Response) {
    const { accessToken } = await jwt.issueTokens(res, {
      userId: 'user-1',
      email: 'user@example.com',
      roles: ['member'],
    })

    return res.json({ accessToken })
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    return jwt.refreshHandler()(req, res)
  }

  @UseGuards()
  @Get('me')
  async me(@Req() req: Request) {
    return req.user
  }
}
