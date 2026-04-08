# jwt-refresh-smart — 프로젝트 계획서

> 액세스 토큰 자동 갱신 · 리프레시 토큰 Rotation · Race Condition 방지를 한 번에 해결하는 Node.js JWT 라이브러리

---

## 목차

1. [왜 만드는가](#1-왜-만드는가)
2. [핵심 개념 정리](#2-핵심-개념-정리)
3. [핵심 기능 스펙](#3-핵심-기능-스펙)
4. [아키텍처 설계](#4-아키텍처-설계)
5. [기술 스택](#5-기술-스택)
6. [프로젝트 구조](#6-프로젝트-구조)
7. [API 설계 상세](#7-api-설계-상세)
8. [토큰 스토어 어댑터](#8-토큰-스토어-어댑터)
9. [Race Condition 방지 설계](#9-race-condition-방지-설계)
10. [토큰 Rotation 설계](#10-토큰-rotation-설계)
11. [구현 로드맵](#11-구현-로드맵)
12. [프레임워크 통합](#12-프레임워크-통합)
13. [테스트 전략](#13-테스트-전략)
14. [보안 설계](#14-보안-설계)
15. [경쟁 분석](#15-경쟁-분석)
16. [패키지 설정](#16-패키지-설정)
17. [GitHub 스타 전략](#17-github-스타-전략)
18. [성공 지표](#18-성공-지표)

---

## 1. 왜 만드는가

### 시장의 문제

Auth0, Supabase, Clerk 같은 SaaS 없이 JWT를 직접 구현하는 팀은 반드시 세 가지 문제에 부딪힌다.

#### 문제 1 — 토큰 갱신 보일러플레이트

```typescript
// 모든 팀이 이걸 반복해서 짜고 있다
app.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.cookies

  // 1. refresh token 유효성 검증
  let payload
  try {
    payload = jwt.verify(refreshToken, process.env.REFRESH_SECRET)
  } catch (e) {
    return res.status(401).json({ error: 'Invalid refresh token' })
  }

  // 2. DB에서 refresh token 존재 여부 확인
  const stored = await db.refreshTokens.findUnique({
    where: { token: refreshToken }
  })
  if (!stored || stored.revokedAt) {
    return res.status(401).json({ error: 'Token revoked' })
  }

  // 3. 새 access token 발급
  const newAccessToken = jwt.sign(
    { userId: payload.userId, plan: payload.plan },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  )

  // 4. rotation: 새 refresh token 발급 + 기존 무효화
  const newRefreshToken = jwt.sign(
    { userId: payload.userId },
    process.env.REFRESH_SECRET,
    { expiresIn: '7d' }
  )
  await db.refreshTokens.update({
    where: { token: refreshToken },
    data: { revokedAt: new Date() }
  })
  await db.refreshTokens.create({ data: { token: newRefreshToken, userId: payload.userId } })

  // 5. 쿠키 설정
  res.cookie('refreshToken', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'strict' })
  res.json({ accessToken: newAccessToken })
})
```

**이 코드의 문제점:**
- 팀마다 다른 구현, 보안 취약점 제각각
- Race Condition 미처리 (동시 요청 시 토큰 충돌)
- Rotation 구현 누락 시 리프레시 토큰 탈취 공격에 취약
- 로그아웃, 토큰 무효화, 기기별 관리가 전부 별개 구현

#### 문제 2 — Race Condition (가장 치명적)

```
클라이언트가 access token 만료 시 동시에 여러 요청을 보내는 상황:

요청 A: "access token 만료! → /auth/refresh 호출"
요청 B: "access token 만료! → /auth/refresh 호출"  ← 동시 발생

→ 두 요청 모두 refresh token으로 갱신 시도
→ Rotation이 켜져 있으면 먼저 도착한 요청이 refresh token을 소진
→ 나중에 도착한 요청: "refresh token already used" → 로그아웃!

→ 사용자가 갑자기 강제 로그아웃됨 (버그 리포트 폭주)
```

#### 문제 3 — 리프레시 토큰 탈취 감지 미비

Rotation 없이 리프레시 토큰을 재사용하면:
- 공격자가 리프레시 토큰을 훔쳐서 영구적으로 사용 가능
- 정상 사용자도 계속 유효한 토큰을 쓰므로 탈취 여부 탐지 불가

### 해결하는 것

- 위 세 문제를 **라이브러리 수준에서 완전히 해결**
- `jsonwebtoken`을 peer dependency로 사용, 기존 코드와 호환
- Redis 또는 DB 기반 토큰 스토어 선택 가능
- 서버 재시작 없이 특정 유저/기기의 토큰 즉시 무효화
- TypeScript 완전 지원

---

## 2. 핵심 개념 정리

### Access Token vs Refresh Token

```
Access Token
├── 수명: 짧음 (5분 ~ 30분)
├── 용도: API 요청 인증
├── 저장: 클라이언트 메모리 (localStorage X → XSS 취약)
└── 검증: stateless (DB 조회 없음) → 빠름

Refresh Token
├── 수명: 김 (7일 ~ 90일)
├── 용도: Access Token 재발급
├── 저장: httpOnly Cookie (XSS 방어)
└── 검증: stateful (DB/Redis 조회 필수) → 무효화 가능
```

### Refresh Token Rotation

```
Before Rotation (취약):
  클라이언트 ──→ 서버: refreshToken=ABC
  서버 ──→ 클라이언트: accessToken=NEW (refreshToken=ABC 유지)
  공격자: refreshToken=ABC 탈취 후 영구 사용 가능 ❌

After Rotation (안전):
  클라이언트 ──→ 서버: refreshToken=ABC
  서버 ──→ 클라이언트: accessToken=NEW, refreshToken=XYZ (ABC 무효화)
  공격자: refreshToken=ABC 재사용 시도 → 탈취 감지 → 해당 유저 전체 세션 무효화 ✅
```

### Silent Refresh (만료 전 선제 갱신)

```
Access Token TTL = 15분
refreshBuffer = 2분 (만료 2분 전 미리 갱신)

타임라인:
0분    토큰 발급
13분   refreshBuffer 진입 → 백그라운드 silent refresh 시작
13.05분 새 토큰 발급 완료 (만료 전에 갱신 완료)
15분   기존 토큰 만료 (이미 새 토큰으로 교체됨)

→ 사용자 입장에서 토큰 만료 없음 (seamless)
```

---

## 3. 핵심 기능 스펙

### 3-1. 기본 사용법

```typescript
import { JwtManager } from 'jwt-refresh-smart'
import { RedisTokenStore } from 'jwt-refresh-smart/stores/redis'
import { createClient } from 'redis'

const redis = createClient({ url: process.env.REDIS_URL })
await redis.connect()

const jwt = new JwtManager({
  access: {
    secret: process.env.JWT_SECRET,
    ttl: '15m',
    algorithm: 'HS256',         // 기본값
  },
  refresh: {
    secret: process.env.REFRESH_SECRET,
    ttl: '7d',
    rotation: true,             // 갱신 시 새 리프레시 토큰 발급
    reuseDetection: true,       // 탈취 감지 (rotation 필수)
  },
  store: new RedisTokenStore(redis),

  // 만료 2분 전 미리 갱신 (서버 사이드 silent refresh 지원 시)
  refreshBuffer: 120,           // 초 단위

  // 쿠키 설정 (자동 처리)
  cookie: {
    name: 'refreshToken',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/auth',
  },
})
```

### 3-2. 로그인 — 토큰 발급

```typescript
app.post('/auth/login', async (req, res) => {
  const user = await validateCredentials(req.body.email, req.body.password)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })

  // 한 줄로 access + refresh 토큰 발급 + 쿠키 세팅
  const { accessToken, refreshToken } = await jwt.issueTokens(res, {
    // access token payload (공개 정보만)
    userId: user.id,
    email: user.email,
    plan: user.plan,
    roles: user.roles,
  }, {
    // refresh token에만 저장되는 메타데이터
    deviceId: req.headers['x-device-id'],
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  })

  res.json({ accessToken })
  // refreshToken은 httpOnly 쿠키로 자동 설정됨
})
```

### 3-3. 토큰 갱신 엔드포인트

```typescript
// 이 한 줄이 위에서 본 50줄짜리 코드를 대체한다
app.post('/auth/refresh', jwt.refreshHandler())

// 내부적으로 처리하는 것:
// 1. 쿠키에서 refresh token 추출
// 2. 서명 검증
// 3. store에서 유효성 확인 (revoke 여부)
// 4. reuseDetection: 이미 사용된 토큰이면 → 해당 유저 전체 세션 무효화 + 401
// 5. Race Condition 방지: mutex로 동시 갱신 요청 1개만 처리
// 6. rotation: 새 refresh token 발급 + 기존 무효화
// 7. 새 access token + refresh token(쿠키) 응답
```

### 3-4. 미들웨어로 API 보호

```typescript
// 미들웨어: access token 검증
app.use('/api', jwt.authenticate())

// 선택적: 만료 임박 시 새 토큰을 응답 헤더에 포함
app.use('/api', jwt.authenticate({
  // 만료 2분 미만 남으면 헤더에 새 토큰 포함
  rotateOnResponse: true,  // Authorization-Refreshed: Bearer <newToken>
}))

// 라우트에서 유저 정보 접근
app.get('/api/me', jwt.authenticate(), (req, res) => {
  req.user.userId  // string — 타입 자동 추론
  req.user.email   // string
  req.user.plan    // string
  res.json(req.user)
})
```

### 3-5. 로그아웃

```typescript
app.post('/auth/logout', jwt.authenticate(), async (req, res) => {
  // 현재 기기만 로그아웃
  await jwt.revokeCurrentSession(req, res)

  // 또는: 모든 기기에서 로그아웃
  await jwt.revokeAllSessions(req.user.userId)

  // 또는: 특정 기기만 로그아웃 (기기 관리 화면에서)
  await jwt.revokeSession(req.user.userId, deviceId)

  res.json({ success: true })
})
```

### 3-6. 활성 세션 목록 조회

```typescript
app.get('/auth/sessions', jwt.authenticate(), async (req, res) => {
  const sessions = await jwt.getSessions(req.user.userId)
  // [
  //   {
  //     sessionId: 'sess_abc123',
  //     deviceId: 'iphone-14-pro',
  //     userAgent: 'Mozilla/5.0 ...',
  //     ip: '121.xxx.xxx.xxx',
  //     createdAt: '2025-06-01T...',
  //     lastUsedAt: '2025-06-15T...',
  //     isCurrent: true,
  //   },
  //   ...
  // ]
  res.json(sessions)
})
```

### 3-7. 커스텀 페이로드 타입 (TypeScript)

```typescript
// jwt.d.ts — 프로젝트 루트에 추가
import 'jwt-refresh-smart'

declare module 'jwt-refresh-smart' {
  interface AccessTokenPayload {
    userId: string
    email: string
    plan: 'free' | 'pro' | 'enterprise'
    roles: string[]
  }
}

// 이후 req.user.plan, req.user.roles 등 타입 자동 완성
```

### 3-8. 토큰 탈취 감지 및 대응

```typescript
// reuseDetection: true 설정 시
// 이미 사용된(rotation된) refresh token으로 요청이 오면:

jwt.on('token:reuse-detected', async (event) => {
  console.warn(`[SECURITY] Refresh token reuse detected!
    userId: ${event.userId}
    tokenId: ${event.tokenId}
    ip: ${event.ip}
    userAgent: ${event.userAgent}
  `)

  // 자동으로 해당 유저의 모든 세션 무효화 (라이브러리 내부)
  // 추가 대응: 보안 알림 이메일 발송
  await emailService.sendSecurityAlert(event.userId, {
    type: 'token_reuse',
    ip: event.ip,
    time: event.detectedAt,
  })

  // 추가 대응: Slack 알림
  await slackService.notify('#security-alerts', `토큰 탈취 의심: userId=${event.userId}`)
})
```

### 3-9. 토큰 블랙리스트 (즉시 무효화)

```typescript
// 특정 액세스 토큰을 즉시 무효화 (비밀번호 변경, 계정 정지 등)
// JWT는 stateless라 원래 불가능하지만, 짧은 TTL 내에서 블랙리스트로 해결

await jwt.blacklistToken(accessToken, {
  reason: 'password_changed',
  userId: user.id,
})

// 미들웨어에서 자동으로 블랙리스트 확인
// (Redis SET에 토큰 jti 저장, TTL = 토큰 잔여 만료 시간)
```

---

## 4. 아키텍처 설계

### 전체 컴포넌트

```
JwtManager (공개 API)
│
├── TokenIssuer          — 토큰 발급 (sign, 쿠키 설정)
├── TokenVerifier        — 토큰 검증 (verify, 블랙리스트 확인)
├── RefreshCoordinator   — 갱신 오케스트레이터
│     ├── SessionMutex   — Race Condition 방지 (핵심)
│     ├── RotationEngine — Refresh Token Rotation
│     └── ReuseDetector  — 탈취 감지
├── SessionManager       — 세션 목록, 개별/전체 무효화
├── BlacklistManager     — 액세스 토큰 즉시 무효화
├── EventEmitter         — 보안 이벤트 (탈취 감지 등)
│
└── TokenStore (interface)
      ├── RedisTokenStore
      ├── PrismaTokenStore
      ├── DrizzleTokenStore
      └── MemoryTokenStore (테스트용)
```

### 갱신 요청 처리 흐름

```
클라이언트 요청 (POST /auth/refresh)
    │
    ▼
쿠키에서 refreshToken 추출
    │
    ▼
jwt.verify(refreshToken, REFRESH_SECRET)  → 서명 실패 시 401
    │
    ▼
store.getSession(tokenId)                  → 존재하지 않으면 401
    │
    ├── revokedAt 있음 → ReuseDetector 발동
    │       │
    │       ▼
    │   store.revokeAllByUserId(userId)    → 전체 세션 무효화
    │   emit('token:reuse-detected')
    │   401 응답
    │
    └── revokedAt 없음 (정상)
            │
            ▼
        SessionMutex.acquire(userId)       → 동시 요청 직렬화
            │
            ├── 이미 갱신 진행 중 → 완료 대기 → 새 토큰 반환 (재사용)
            │
            └── 갱신 진행 (최초 요청)
                    │
                    ▼
                RotationEngine
                    ├── 새 refreshToken 생성 + store.create()
                    ├── 기존 refreshToken store.revoke()
                    └── 새 accessToken 생성
                    │
                    ▼
                SessionMutex.release(userId)
                    │
                    ▼
                쿠키 갱신 + accessToken 응답
```

---

## 5. 기술 스택

| 영역 | 선택 | 이유 |
|---|---|---|
| 언어 | TypeScript 5.x | |
| JWT 서명/검증 | `jsonwebtoken` (peer) | 기존 코드 호환 |
| 쿠키 파싱 | `cookie` | 경량, 의존성 없음 |
| 뮤텍스 구현 | `async-mutex` | Redis 없이도 동작하는 인메모리 뮤텍스 |
| Redis 분산 뮤텍스 | `redlock` | 멀티 인스턴스 환경 Race Condition 방지 |
| Redis 클라이언트 | `ioredis` / `redis` (peer) | 둘 다 지원 |
| Prisma | `@prisma/client` (peer) | |
| 암호화 | Node.js 내장 `crypto` | 외부 의존성 없음 |
| 빌드 | `tsup` | ESM + CJS |
| 테스트 | `vitest` | |
| 시간 처리 | `ms` | TTL 문자열 파싱 (`'15m'`, `'7d'`) |

---

## 6. 프로젝트 구조

```
jwt-refresh-smart/
├── src/
│   ├── index.ts                      # JwtManager 클래스 (진입점)
│   │
│   ├── core/
│   │   ├── JwtManager.ts             # 메인 클래스
│   │   ├── TokenIssuer.ts            # 토큰 발급 로직
│   │   ├── TokenVerifier.ts          # 토큰 검증 + 블랙리스트
│   │   └── RefreshCoordinator.ts     # 갱신 오케스트레이터
│   │
│   ├── rotation/
│   │   ├── RotationEngine.ts         # Refresh Token Rotation
│   │   └── ReuseDetector.ts          # 토큰 재사용(탈취) 감지
│   │
│   ├── mutex/
│   │   ├── SessionMutex.ts           # 추상 인터페이스
│   │   ├── InMemoryMutex.ts          # 단일 인스턴스용
│   │   └── RedlockMutex.ts           # 멀티 인스턴스 분산 뮤텍스
│   │
│   ├── session/
│   │   ├── SessionManager.ts         # 세션 목록/무효화 관리
│   │   └── BlacklistManager.ts       # 액세스 토큰 블랙리스트
│   │
│   ├── stores/
│   │   ├── BaseStore.ts              # 스토어 인터페이스
│   │   ├── RedisTokenStore.ts        # Redis 스토어
│   │   ├── PrismaTokenStore.ts       # Prisma 스토어
│   │   ├── DrizzleTokenStore.ts      # Drizzle 스토어
│   │   └── MemoryTokenStore.ts       # 인메모리 (테스트용)
│   │
│   ├── middleware/
│   │   ├── authenticate.ts           # access token 검증 미들웨어
│   │   └── refreshHandler.ts         # refresh 엔드포인트 핸들러
│   │
│   ├── integrations/
│   │   ├── express.ts
│   │   ├── fastify.ts
│   │   ├── nextjs.ts                 # App Router Route Handler
│   │   └── nestjs.ts                 # NestJS Guard + Decorator
│   │
│   ├── testing/
│   │   └── MockTokenStore.ts
│   │
│   └── types.ts                      # 공개 타입 정의
│
├── tests/
│   ├── unit/
│   │   ├── token-issuer.test.ts
│   │   ├── token-verifier.test.ts
│   │   ├── rotation-engine.test.ts
│   │   ├── reuse-detector.test.ts
│   │   └── blacklist.test.ts
│   ├── integration/
│   │   ├── refresh-flow.test.ts      # 전체 갱신 흐름 E2E
│   │   ├── race-condition.test.ts    # 동시 요청 시뮬레이션 (핵심)
│   │   ├── redis-store.test.ts
│   │   └── prisma-store.test.ts
│   └── security/
│       ├── reuse-detection.test.ts   # 탈취 시나리오
│       └── blacklist.test.ts
│
├── examples/
│   ├── express-complete/             # 로그인/로그아웃/갱신 전체 예제
│   ├── nextjs-app-router/            # Next.js Route Handler 예제
│   ├── nestjs/                       # NestJS Guard 예제
│   ├── multi-device/                 # 기기별 세션 관리 예제
│   └── token-reuse-demo/            # 탈취 감지 시연 예제
│
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── README.md
```

---

## 7. API 설계 상세

### `JwtManager` 클래스

```typescript
class JwtManager<TPayload extends AccessTokenPayload = AccessTokenPayload> {
  constructor(options: JwtManagerOptions<TPayload>)

  // ── 토큰 발급 ──
  // access + refresh 토큰 발급, 쿠키 자동 설정
  issueTokens(
    res: Response,
    payload: TPayload,
    sessionMeta?: SessionMeta
  ): Promise<{ accessToken: string; refreshToken: string; sessionId: string }>

  // access token만 발급 (refresh는 별도 처리 시)
  signAccessToken(payload: TPayload): string

  // refresh token만 발급
  signRefreshToken(userId: string, sessionMeta?: SessionMeta): Promise<string>

  // ── 토큰 검증 ──
  // access token 검증 → payload 반환
  verifyAccessToken(token: string): TPayload

  // refresh token 검증 → session 정보 반환
  verifyRefreshToken(token: string): Promise<RefreshTokenSession>

  // ── 미들웨어/핸들러 ──
  // Express/Fastify 미들웨어
  authenticate(options?: AuthenticateOptions): RequestHandler

  // POST /auth/refresh 핸들러 (한 줄로 완성)
  refreshHandler(options?: RefreshHandlerOptions): RequestHandler

  // ── 세션 관리 ──
  // 현재 요청의 세션 무효화 (로그아웃)
  revokeCurrentSession(req: Request, res: Response): Promise<void>

  // 특정 유저의 특정 세션 무효화
  revokeSession(userId: string, sessionId: string): Promise<void>

  // 특정 유저의 모든 세션 무효화 (비밀번호 변경, 계정 정지)
  revokeAllSessions(userId: string): Promise<void>

  // 세션 목록 조회
  getSessions(userId: string): Promise<SessionInfo[]>

  // ── 블랙리스트 ──
  // 현재 유효한 access token을 즉시 무효화
  blacklistToken(token: string, reason?: string): Promise<void>

  // ── 이벤트 ──
  on(event: 'token:reuse-detected', handler: (event: ReuseEvent) => void): void
  on(event: 'token:refreshed', handler: (event: RefreshEvent) => void): void
  on(event: 'token:revoked', handler: (event: RevokeEvent) => void): void
  on(event: 'store:error', handler: (error: Error) => void): void
}
```

### 옵션 타입 상세

```typescript
interface JwtManagerOptions<TPayload> {
  access: {
    secret: string | Buffer
    ttl: string | number         // '15m', '1h', 900 (초)
    algorithm?: Algorithm        // 기본값: 'HS256'
    issuer?: string              // JWT iss 클레임
    audience?: string            // JWT aud 클레임
  }
  refresh: {
    secret: string | Buffer
    ttl: string | number         // '7d', '30d'
    rotation?: boolean           // 기본값: true
    reuseDetection?: boolean     // 기본값: true (rotation 필수)
    absoluteExpiry?: string      // rotation 후에도 이 기간 지나면 강제 재로그인
                                 // 예: '90d' → 90일마다 반드시 재로그인
  }
  store: TokenStore
  mutex?: 'memory' | 'redis' | MutexAdapter
  // 'memory': 단일 서버 인스턴스 (기본값)
  // 'redis': 다중 서버 인스턴스 (Redlock 기반)

  cookie?: {
    name?: string                // 기본값: 'refreshToken'
    httpOnly?: boolean           // 기본값: true
    secure?: boolean             // 기본값: NODE_ENV === 'production'
    sameSite?: 'strict' | 'lax' | 'none'  // 기본값: 'strict'
    domain?: string
    path?: string                // 기본값: '/'
    maxAge?: number              // 기본값: refresh ttl (초)
  }

  // access token 만료 N초 전에 응답 헤더에 새 토큰 포함
  refreshBuffer?: number         // 기본값: 0 (비활성)

  // store 오류 시 fallback 동작
  onStoreError?: 'throw' | 'warn'  // 기본값: 'warn' (가용성 우선)

  // 토큰에서 컨텍스트 추출 (로깅용)
  extractContext?: (req: Request) => Record<string, unknown>
}

interface SessionMeta {
  deviceId?: string
  userAgent?: string
  ip?: string
  [key: string]: unknown         // 커스텀 메타데이터
}

interface SessionInfo {
  sessionId: string
  userId: string
  deviceId?: string
  userAgent?: string
  ip?: string
  createdAt: Date
  lastUsedAt: Date
  expiresAt: Date
  isCurrent: boolean             // 현재 요청의 세션 여부
}
```

---

## 8. 토큰 스토어 어댑터

### 스토어 인터페이스

```typescript
interface TokenStore {
  // refresh token 세션 생성
  createSession(session: RefreshTokenSession): Promise<void>

  // refresh token으로 세션 조회
  getSession(tokenId: string): Promise<RefreshTokenSession | null>

  // 세션 무효화 (revokedAt 설정)
  revokeSession(tokenId: string): Promise<void>

  // 특정 유저의 모든 세션 무효화
  revokeAllByUserId(userId: string): Promise<void>

  // 특정 유저의 활성 세션 목록
  getSessionsByUserId(userId: string): Promise<RefreshTokenSession[]>

  // 세션 마지막 사용 시간 업데이트
  touchSession(tokenId: string): Promise<void>

  // access token 블랙리스트
  blacklistToken(jti: string, expiresAt: Date): Promise<void>
  isBlacklisted(jti: string): Promise<boolean>

  // 만료된 세션 정리 (선택적, 일부 스토어는 TTL로 자동 처리)
  cleanup?(): Promise<void>
}

interface RefreshTokenSession {
  tokenId: string          // JWT jti 클레임 (UUID)
  userId: string
  token: string            // refresh token 원본 (해시 저장 권장)
  deviceId?: string
  userAgent?: string
  ip?: string
  createdAt: Date
  lastUsedAt: Date
  expiresAt: Date
  revokedAt?: Date         // 설정되면 무효화된 토큰
  revokedReason?: string   // 'logout' | 'rotation' | 'reuse_detected' | 'password_changed'
  parentTokenId?: string   // rotation 전 부모 tokenId (reuse detection용)
  metadata?: Record<string, unknown>
}
```

### RedisTokenStore — 키 설계

```typescript
// 키 네임스페이스
const KEYS = {
  // refresh token 세션 (Hash)
  session: (tokenId: string) => `jwt:session:${tokenId}`,

  // 유저별 세션 목록 (Sorted Set, score = expiresAt timestamp)
  userSessions: (userId: string) => `jwt:user:${userId}:sessions`,

  // access token 블랙리스트 (Set)
  blacklist: (jti: string) => `jwt:blacklist:${jti}`,

  // 뮤텍스 키 (Redlock)
  mutex: (userId: string) => `jwt:mutex:${userId}`,
}

// 예시 데이터
// jwt:session:uuid-1234  → HSET { tokenId, userId, createdAt, ... }
//                        → EXPIRE = refresh token TTL
//
// jwt:user:42:sessions   → ZADD score=expiresAt member=tokenId
//                        → 만료된 세션 자동 정리: ZREMRANGEBYSCORE -inf now
//
// jwt:blacklist:jti-xxx  → SET "1"
//                        → EXPIRE = access token 잔여 만료 시간
```

### PrismaTokenStore — 스키마

```prisma
model RefreshTokenSession {
  id             String    @id @default(cuid())
  tokenId        String    @unique          // JWT jti (UUID)
  userId         String
  tokenHash      String                     // SHA-256 해시 (원본 저장 X)
  deviceId       String?
  userAgent      String?   @db.Text
  ip             String?
  createdAt      DateTime  @default(now())
  lastUsedAt     DateTime  @default(now())
  expiresAt      DateTime
  revokedAt      DateTime?
  revokedReason  String?
  parentTokenId  String?
  metadata       Json?

  @@index([userId, expiresAt])
  @@index([userId, revokedAt])
  @@index([expiresAt])            // 만료 세션 정리용
}

model TokenBlacklist {
  id         String   @id @default(cuid())
  jti        String   @unique    // access token jti
  userId     String
  reason     String?
  expiresAt  DateTime            // 이 시간 지나면 삭제해도 됨
  createdAt  DateTime @default(now())

  @@index([expiresAt])           // 정리용
}
```

CLI로 스키마 자동 추가:
```bash
npx jwt-refresh-smart prisma:setup
# → prisma/schema.prisma에 두 모델 자동 추가
# → npx prisma migrate dev --name add-jwt-sessions 실행
```

### 토큰 해시 저장 (보안)

```typescript
// refresh token 원본을 DB에 저장하면 DB 탈취 시 모든 세션 무효화 가능
// → SHA-256 해시로 저장

import { createHash } from 'crypto'

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

// store.createSession()에서 자동 처리
// getSession()에서 자동으로 해시 비교
```

---

## 9. Race Condition 방지 설계

### 문제 상황 재현

```typescript
// 동시에 3개의 요청이 /auth/refresh 를 호출하는 상황
// (클라이언트 코드에서 access token 만료 시 여러 요청이 동시에 갱신 시도)

const [r1, r2, r3] = await Promise.all([
  fetch('/auth/refresh', { method: 'POST', credentials: 'include' }),
  fetch('/auth/refresh', { method: 'POST', credentials: 'include' }),
  fetch('/auth/refresh', { method: 'POST', credentials: 'include' }),
])

// rotation: true인 경우:
// r1: refreshToken=ABC → 성공 → refreshToken=XYZ 발급, ABC 무효화
// r2: refreshToken=ABC → 실패 (ABC 이미 사용됨) → reuseDetection → 전체 로그아웃!
// r3: refreshToken=ABC → 실패 (ABC 이미 사용됨) → reuseDetection → 전체 로그아웃!
//
// 결과: 정상 사용자가 갑자기 로그아웃됨
```

### 해결: SessionMutex

```typescript
// InMemoryMutex (단일 서버 인스턴스)
class InMemoryMutex implements MutexAdapter {
  private locks = new Map<string, Promise<void>>()

  async acquire(key: string): Promise<() => void> {
    // 이미 진행 중인 갱신이 있으면 완료될 때까지 대기
    while (this.locks.has(key)) {
      await this.locks.get(key)
    }

    let release!: () => void
    const lock = new Promise<void>(resolve => { release = resolve })
    this.locks.set(key, lock)

    return () => {
      this.locks.delete(key)
      release()
    }
  }
}

// RefreshCoordinator에서 사용
class RefreshCoordinator {
  async refresh(refreshToken: string, req: Request, res: Response) {
    const payload = await this.verifyRefreshToken(refreshToken)
    const userId = payload.userId

    // userId 기준으로 뮤텍스 획득
    const release = await this.mutex.acquire(`refresh:${userId}`)

    try {
      // 뮤텍스 획득 후 토큰 다시 확인 (대기 중에 이미 갱신됐을 수 있음)
      const session = await this.store.getSession(payload.jti)

      if (session?.revokedAt) {
        // 대기 중에 이미 갱신됨 → 새 토큰이 쿠키에 있음 → 재시도 유도
        // 실제 탈취가 아님! 정상 race condition
        return { status: 'already_refreshed', retryWithNewCookie: true }
      }

      // 정상 갱신 진행
      return await this.performRotation(session, req, res)
    } finally {
      release()
    }
  }
}
```

### 분산 환경 (멀티 서버 인스턴스)

```typescript
// 서버가 여러 대일 때는 Redis 기반 분산 뮤텍스 (Redlock)
import { RedlockMutex } from 'jwt-refresh-smart/mutex/redis'

const jwt = new JwtManager({
  // ...
  mutex: new RedlockMutex(redis, {
    retryCount: 5,
    retryDelay: 50,   // ms
    lockTtl: 2000,    // 2초 안에 갱신 완료 안 되면 자동 해제
  }),
})
```

### 클라이언트 사이드 Race Condition도 해결

```typescript
// 클라이언트(브라우저)에서도 동일한 문제 발생
// → 라이브러리가 응답 헤더로 가이드 제공

// 서버 응답
HTTP/1.1 409 Conflict
X-Refresh-Retry: true
// 의미: "이미 다른 요청이 갱신 중. 쿠키 새로고침 후 원래 요청 재시도"

// 클라이언트 처리 (예시)
if (response.status === 409 && response.headers.get('X-Refresh-Retry')) {
  // 잠시 대기 후 원래 API 요청 재시도 (갱신된 쿠키 자동 사용)
  await sleep(100)
  return retryOriginalRequest()
}
```

---

## 10. 토큰 Rotation 설계

### Rotation 흐름

```typescript
class RotationEngine {
  async rotate(
    oldSession: RefreshTokenSession,
    req: Request,
    res: Response
  ): Promise<RotationResult> {

    const newTokenId = crypto.randomUUID()

    // 1. 새 refresh token 생성
    const newRefreshToken = jwt.sign(
      { userId: oldSession.userId, jti: newTokenId },
      this.options.refresh.secret,
      { expiresIn: this.options.refresh.ttl }
    )

    // 2. 새 access token 생성
    const newAccessToken = jwt.sign(
      await this.loadUserPayload(oldSession.userId),
      this.options.access.secret,
      { expiresIn: this.options.access.ttl }
    )

    // 3. DB/Redis 원자적 업데이트
    await this.store.createSession({
      tokenId: newTokenId,
      userId: oldSession.userId,
      token: hashToken(newRefreshToken),
      parentTokenId: oldSession.tokenId,   // 부모 추적 (reuse detection)
      deviceId: oldSession.deviceId,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      createdAt: new Date(),
      lastUsedAt: new Date(),
      expiresAt: addSeconds(new Date(), parseTTL(this.options.refresh.ttl)),
    })

    // 4. 기존 token 무효화 (rotation 표시)
    await this.store.revokeSession(oldSession.tokenId, 'rotation')

    // 5. 새 refresh token 쿠키 설정
    res.cookie(this.options.cookie.name, newRefreshToken, this.cookieOptions)

    return { accessToken: newAccessToken, sessionId: newTokenId }
  }
}
```

### Absolute Expiry (절대 만료)

```typescript
// rotation을 계속해도 최대 N일 후에는 반드시 재로그인
// 세션 하이재킹 피해 최소화 (예: 탈취된 토큰도 90일 후 자동 만료)

const jwt = new JwtManager({
  refresh: {
    ttl: '7d',
    rotation: true,
    absoluteExpiry: '90d',  // rotation을 아무리 해도 90일 후 강제 로그아웃
  },
})

// 구현: parentTokenId 체인을 따라가 최초 발급 시각 확인
// 또는: 세션 메타데이터에 originalCreatedAt 저장
async function checkAbsoluteExpiry(session: RefreshTokenSession): Promise<boolean> {
  const rootSession = await findRootSession(session)  // parentTokenId 체인 추적
  const ageMs = Date.now() - rootSession.createdAt.getTime()
  return ageMs > parseTTL(absoluteExpiry)
}
```

---

## 11. 구현 로드맵

### Phase 1 — 코어 토큰 발급/검증 (1~2주)

- [ ] `JwtManagerOptions` 타입 설계 완료
- [ ] `TokenIssuer` 구현 (access + refresh 토큰 서명)
- [ ] `TokenVerifier` 구현 (검증, 만료 체크)
- [ ] `MemoryTokenStore` 구현 (테스트용)
- [ ] `JwtManager.issueTokens()` 구현
- [ ] `JwtManager.authenticate()` 미들웨어
- [ ] 쿠키 자동 설정/파싱 로직
- [ ] 기본 유닛 테스트 100% 커버리지

### Phase 2 — Rotation + Race Condition (2~3주)

- [ ] `RotationEngine` 구현
- [ ] `ReuseDetector` 구현 (parentTokenId 체인 분석)
- [ ] `InMemoryMutex` 구현
- [ ] `RefreshCoordinator` (뮤텍스 + rotation 통합)
- [ ] `JwtManager.refreshHandler()` 구현
- [ ] Race Condition 동시 요청 테스트 (핵심)
- [ ] Reuse Detection 시나리오 테스트

### Phase 3 — Redis 스토어 (3~4주)

- [ ] `RedisTokenStore` 구현 (ioredis + redis v4)
- [ ] `RedlockMutex` 구현 (분산 뮤텍스)
- [ ] 세션 만료 자동 정리 (Sorted Set + ZREMRANGEBYSCORE)
- [ ] access token 블랙리스트 (Redis SET + TTL)
- [ ] Redis 장애 시 fallback 처리

### Phase 4 — DB 스토어 (4~5주)

- [ ] `PrismaTokenStore` 구현
- [ ] `DrizzleTokenStore` 구현
- [ ] `npx jwt-refresh-smart prisma:setup` CLI
- [ ] 만료 세션 자동 정리 cron 유틸리티
- [ ] DB 스토어 통합 테스트 (SQLite)

### Phase 5 — 세션 관리 & 보안 (5~6주)

- [ ] `SessionManager` (목록, 개별/전체 무효화)
- [ ] `BlacklistManager` (access token 즉시 무효화)
- [ ] Absolute Expiry 구현
- [ ] 보안 이벤트 시스템 (`on('token:reuse-detected')`)
- [ ] 토큰 해시 저장 (SHA-256)
- [ ] `JwtManager.revokeCurrentSession()` / `revokeAllSessions()`

### Phase 6 — 프레임워크 통합 (6~7주)

- [ ] Express 미들웨어 완성
- [ ] Fastify 플러그인
- [ ] Next.js App Router Route Handler
- [ ] NestJS Guard + Decorator
- [ ] 각 프레임워크 예제 프로젝트

### Phase 7 — 런치 (7~8주)

- [ ] 문서 사이트 (VitePress)
- [ ] Race Condition 시각화 다이어그램 README
- [ ] 보안 체크리스트 문서
- [ ] npm 배포
- [ ] 런치 블로그 포스팅

---

## 12. 프레임워크 통합

### Express 전체 예제

```typescript
import express from 'express'
import { JwtManager } from 'jwt-refresh-smart'
import { RedisTokenStore } from 'jwt-refresh-smart/stores/redis'

const app = express()
const jwt = new JwtManager({
  access:  { secret: process.env.JWT_SECRET!, ttl: '15m' },
  refresh: { secret: process.env.REFRESH_SECRET!, ttl: '7d', rotation: true },
  store:   new RedisTokenStore(redis),
  mutex:   'redis',  // 멀티 인스턴스 환경
})

// 로그인
app.post('/auth/login', async (req, res) => {
  const user = await validateUser(req.body)
  const { accessToken } = await jwt.issueTokens(res, {
    userId: user.id, email: user.email, plan: user.plan
  }, { ip: req.ip, userAgent: req.headers['user-agent'] })
  res.json({ accessToken })
})

// 토큰 갱신 (한 줄)
app.post('/auth/refresh', jwt.refreshHandler())

// 로그아웃
app.post('/auth/logout', jwt.authenticate(), async (req, res) => {
  await jwt.revokeCurrentSession(req, res)
  res.json({ success: true })
})

// 세션 목록 (기기 관리)
app.get('/auth/sessions', jwt.authenticate(), async (req, res) => {
  res.json(await jwt.getSessions(req.user.userId))
})

// 특정 세션 종료
app.delete('/auth/sessions/:sessionId', jwt.authenticate(), async (req, res) => {
  await jwt.revokeSession(req.user.userId, req.params.sessionId)
  res.json({ success: true })
})

// 보호된 API
app.get('/api/me', jwt.authenticate(), (req, res) => {
  res.json(req.user)
})
```

### Next.js App Router

```typescript
// app/api/auth/login/route.ts
import { jwt } from '@/lib/jwt'

export async function POST(request: Request) {
  const { email, password } = await request.json()
  const user = await validateUser(email, password)

  const response = NextResponse.json({ success: true })
  const { accessToken } = await jwt.issueTokens(response, {
    userId: user.id, email: user.email, plan: user.plan
  })

  return NextResponse.json({ accessToken }, {
    headers: response.headers  // 쿠키 헤더 복사
  })
}

// app/api/auth/refresh/route.ts
import { jwt } from '@/lib/jwt'

export const POST = jwt.refreshHandler()  // 한 줄

// app/api/me/route.ts
import { jwt } from '@/lib/jwt'

export async function GET(request: Request) {
  const user = await jwt.verifyRequest(request)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  return NextResponse.json(user)
}

// middleware.ts (선택적: Edge Runtime에서 토큰 검증)
import { jwtMiddleware } from 'jwt-refresh-smart/integrations/nextjs'

export const middleware = jwtMiddleware({
  secret: process.env.JWT_SECRET!,
  publicPaths: ['/auth/login', '/auth/refresh', '/'],
})
```

### NestJS

```typescript
// auth.module.ts
import { JwtRefreshModule } from 'jwt-refresh-smart/integrations/nestjs'

@Module({
  imports: [
    JwtRefreshModule.forRoot({
      access:  { secret: process.env.JWT_SECRET, ttl: '15m' },
      refresh: { secret: process.env.REFRESH_SECRET, ttl: '7d', rotation: true },
      store:   new RedisTokenStore(redis),
    }),
  ],
})
export class AuthModule {}

// auth.controller.ts
import { JwtUser, CurrentSession } from 'jwt-refresh-smart/integrations/nestjs'

@Controller('auth')
export class AuthController {
  constructor(private readonly jwt: JwtManagerService) {}

  @Post('login')
  async login(@Body() dto: LoginDto, @Res() res: Response) {
    const user = await this.authService.validate(dto)
    const { accessToken } = await this.jwt.issueTokens(res, user)
    return res.json({ accessToken })
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res() res: Response) {
    return this.jwt.refreshHandler()(req, res)
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@JwtUser() user: AccessTokenPayload) {
    return user
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  getSessions(@JwtUser() user: AccessTokenPayload) {
    return this.jwt.getSessions(user.userId)
  }
}
```

---

## 13. 테스트 전략

### Race Condition 핵심 테스트

```typescript
// tests/integration/race-condition.test.ts
describe('Race Condition Prevention', () => {
  it('handles 10 simultaneous refresh requests without false reuse detection', async () => {
    const { accessToken, refreshToken } = await issueTokens(user)

    // 10개 동시 요청 시뮬레이션
    const requests = Array.from({ length: 10 }, () =>
      request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${refreshToken}`)
    )

    const responses = await Promise.all(requests)

    // 모든 응답이 성공이거나 "retry" 상태여야 함
    // 401 Unauthorized가 나오면 안 됨 (false positive reuse detection)
    const unauthorized = responses.filter(r => r.status === 401)
    expect(unauthorized).toHaveLength(0)

    // 성공 응답이 최소 1개
    const successful = responses.filter(r => r.status === 200)
    expect(successful.length).toBeGreaterThanOrEqual(1)

    // 새로 발급된 access token은 모두 유효해야 함
    for (const res of successful) {
      expect(() => jwt.verifyAccessToken(res.body.accessToken)).not.toThrow()
    }
  })

  it('detects actual reuse (attacker scenario)', async () => {
    const { refreshToken } = await issueTokens(user)

    // 정상 갱신 (토큰 소진)
    await request(app)
      .post('/auth/refresh')
      .set('Cookie', `refreshToken=${refreshToken}`)

    // 공격자가 탈취한 원래 토큰으로 재시도 (reuse detection 발동)
    const attackResponse = await request(app)
      .post('/auth/refresh')
      .set('Cookie', `refreshToken=${refreshToken}`)  // 기존 토큰 재사용

    expect(attackResponse.status).toBe(401)

    // 해당 유저의 모든 세션 무효화 확인
    const sessions = await jwt.getSessions(user.id)
    expect(sessions.every(s => s.revokedAt)).toBe(true)

    // 이벤트 발생 확인
    expect(reuseDetectedEvents).toHaveLength(1)
    expect(reuseDetectedEvents[0].userId).toBe(user.id)
  })
})
```

### 보안 시나리오 테스트

```typescript
describe('Security Scenarios', () => {
  it('revokes all sessions when password changes', async () => {
    // 3개 기기에서 로그인
    const sessions = await Promise.all([
      issueTokens(user, { deviceId: 'iphone' }),
      issueTokens(user, { deviceId: 'macbook' }),
      issueTokens(user, { deviceId: 'ipad' }),
    ])

    // 비밀번호 변경
    await jwt.revokeAllSessions(user.id)

    // 모든 refresh token 무효화 확인
    for (const { refreshToken } of sessions) {
      const res = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${refreshToken}`)
      expect(res.status).toBe(401)
    }
  })

  it('blacklisted access token is rejected immediately', async () => {
    const { accessToken } = await issueTokens(user)

    // 토큰이 유효한 상태에서 블랙리스트 등록
    await jwt.blacklistToken(accessToken, 'password_changed')

    // 블랙리스트된 토큰으로 API 요청 → 거부
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', `Bearer ${accessToken}`)

    expect(res.status).toBe(401)
    expect(res.body.error).toBe('Token has been revoked')
  })

  it('absolute expiry forces re-login after 90 days', async () => {
    const { refreshToken } = await issueTokensWithAbsoluteExpiry(user, '90d')

    // 91일 후 시뮬레이션
    jest.setSystemTime(Date.now() + 91 * 24 * 60 * 60 * 1000)

    const res = await request(app)
      .post('/auth/refresh')
      .set('Cookie', `refreshToken=${refreshToken}`)

    expect(res.status).toBe(401)
    expect(res.body.error).toBe('Session expired. Please log in again.')
  })
})
```

### 성능 테스트

```typescript
describe('Performance', () => {
  bench('access token verification (cached secret)', () => {
    jwt.verifyAccessToken(accessToken)
  })
  // 목표: < 0.1ms

  bench('refresh flow (Redis store)', async () => {
    await refreshWithNewToken()
  })
  // 목표: < 10ms (Redis LAN)

  bench('mutex acquire/release (in-memory)', async () => {
    const release = await mutex.acquire('user:1')
    release()
  })
  // 목표: < 0.01ms
})
```

---

## 14. 보안 설계

### 체크리스트 (README에 포함)

```markdown
## 보안 체크리스트

필수 설정:
- [x] refresh.rotation: true           — 매 갱신마다 새 토큰 발급
- [x] refresh.reuseDetection: true     — 탈취 시 전체 세션 무효화
- [x] cookie.httpOnly: true            — XSS로 토큰 탈취 방지
- [x] cookie.secure: true              — HTTPS에서만 쿠키 전송
- [x] cookie.sameSite: 'strict'        — CSRF 방어

권장 설정:
- [ ] mutex: 'redis'                   — 멀티 인스턴스 배포 시
- [ ] refresh.absoluteExpiry: '90d'    — 영구 세션 방지
- [ ] refreshBuffer: 120               — 만료 직전 자동 갱신
- [ ] on('token:reuse-detected')       — 보안 알림 연동

시크릿 관리:
- JWT_SECRET과 REFRESH_SECRET은 반드시 다른 값 사용
- 최소 256비트 엔트로피 (32바이트 이상 랜덤 문자열)
- 생성: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
- 시크릿 로테이션: 새 시크릿으로 마이그레이션 시 grace period 지원
```

### 시크릿 로테이션 지원

```typescript
// JWT 시크릿을 교체해야 할 때 (보안 사고 등)
// 기존 토큰을 즉시 무효화하지 않고 grace period 제공

const jwt = new JwtManager({
  access: {
    secret: process.env.JWT_SECRET_NEW!,
    // 이전 시크릿도 검증에 사용 (발급은 새 시크릿으로만)
    legacySecrets: [process.env.JWT_SECRET_OLD!],
    ttl: '15m',
  },
})
// → 기존 토큰은 만료까지(최대 15분) 자연스럽게 교체됨
// → refresh token도 동일하게 처리
```

### PKCE 지원 (OAuth-like 흐름)

```typescript
// 공개 클라이언트(SPA, 모바일 앱)를 위한 PKCE 지원
const jwt = new JwtManager({
  // ...
  pkce: true,  // refresh 요청 시 code_verifier 검증
})

// 발급 시
const { accessToken, codeChallenge } = await jwt.issueTokens(res, payload, {
  codeChallengeMethod: 'S256',
})

// 갱신 시
POST /auth/refresh
Body: { code_verifier: '...' }
```

---

## 15. 경쟁 분석

| 기능 | jwt-refresh-smart | jsonwebtoken | passport-jwt | nestjs/jwt | jose |
|---|---|---|---|---|---|
| Access Token 발급/검증 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Refresh Token 관리 | ✅ | ❌ | ❌ | ❌ | ❌ |
| Token Rotation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Race Condition 방지 | ✅ 핵심 | ❌ | ❌ | ❌ | ❌ |
| Reuse Detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| 세션 목록/무효화 | ✅ | ❌ | ❌ | ❌ | ❌ |
| Redis 스토어 | ✅ | N/A | N/A | N/A | N/A |
| Prisma 스토어 | ✅ | N/A | N/A | N/A | N/A |
| 멀티 인스턴스 뮤텍스 | ✅ Redlock | N/A | N/A | N/A | N/A |
| TypeScript 완전 지원 | ✅ | ⚠️ | ⚠️ | ✅ | ✅ |
| Access Token 블랙리스트 | ✅ | ❌ | ❌ | ❌ | ❌ |
| 쿠키 자동 처리 | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## 16. 패키지 설정

### package.json

```json
{
  "name": "jwt-refresh-smart",
  "version": "0.1.0",
  "description": "JWT refresh token rotation, race condition prevention, and reuse detection for Node.js",
  "keywords": [
    "jwt", "refresh-token", "token-rotation", "race-condition",
    "authentication", "session", "typescript", "redis", "prisma"
  ],
  "exports": {
    ".": {
      "import": "./dist/index.mjs",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    },
    "./stores/redis": { "...": "..." },
    "./stores/prisma": { "...": "..." },
    "./stores/drizzle": { "...": "..." },
    "./integrations/express": { "...": "..." },
    "./integrations/fastify": { "...": "..." },
    "./integrations/nextjs": { "...": "..." },
    "./integrations/nestjs": { "...": "..." },
    "./testing": { "...": "..." }
  },
  "peerDependencies": {
    "jsonwebtoken": ">=9.0.0",
    "ioredis": ">=4.0.0",
    "redis": ">=4.0.0",
    "@prisma/client": ">=4.0.0"
  },
  "peerDependenciesMeta": {
    "ioredis":          { "optional": true },
    "redis":            { "optional": true },
    "@prisma/client":   { "optional": true }
  },
  "dependencies": {
    "async-mutex": "^0.4.0",
    "ms": "^2.1.3",
    "cookie": "^0.6.0"
  },
  "optionalDependencies": {
    "redlock": "^5.0.0"
  }
}
```

---

## 17. GitHub 스타 전략

### README 핵심 메시지

```markdown
# jwt-refresh-smart

> JWT refresh token rotation + race condition prevention, in one package.

## The problem no one talks about

When your access token expires and the user has 3 tabs open,
all 3 tabs try to refresh simultaneously.
If you have rotation enabled, 2 of them get **401 Unauthorized** — and the user gets logged out.

This library fixes that.
```

### 런치 채널

1. **Reddit r/node** — "I built a JWT library that solves the refresh token race condition problem" (구체적 문제 제시)
2. **Reddit r/webdev** — 보안 관점으로 "Why your JWT implementation is probably broken"
3. **Hacker News Show HN** — Race Condition 다이어그램 포함, 기술적 깊이로 관심 유발
4. **Dev.to** — "The JWT refresh race condition bug that's silently logging your users out" 제목으로 SEO 최적화
5. **NestJS Discord** — #showcase 채널
6. **Prisma Discord** — #showcase 채널
7. **Next.js Discord** — authentication 관련 채널
8. **한국** — Velog에 "JWT 갱신 Race Condition이 왜 발생하고 어떻게 막는가" 포스팅

### 지속적 성장

- `jsonwebtoken` GitHub Issues에서 "refresh token" 관련 이슈에 자연스럽게 언급
- `passport-jwt` Issues에서 rotation/race condition 관련 이슈 언급
- NestJS 공식 문서 "Authentication" 섹션의 한계점 논의에서 언급
- "jwt refresh token rotation node.js" 구글 검색 상단 노출 목표 (SEO)
- JWT.io 커뮤니티 포럼에 포스팅

---

## 18. 성공 지표

| 기간 | 목표 스타 수 | npm 주간 다운로드 | 주요 마일스톤 |
|---|---|---|---|
| 런치 당일 | 60+ | — | Reddit / HN 포스팅 |
| 1개월 | 400+ | 2,000+ | Dev.to 블로그 바이럴 |
| 3개월 | 1,500+ | 8,000+ | NestJS 커뮤니티 채택 |
| 6개월 | 5,000+ | 30,000+ | 주요 보일러플레이트 포함 |
| 1년 | 12,000+ | 80,000+ | de-facto JWT refresh 솔루션 포지셔닝 |

### 모니터링 지표

- npm 주간 다운로드 (npmtrends.com)
- "jwt refresh race condition" 검색 순위
- GitHub Issues 질문 수 (커뮤니티 크기 지표)
- 외부 기여 PR 수
- 의존하는 패키지 수 (npm dependents)
- Security audit 통과 여부 (Snyk, Socket.dev)
