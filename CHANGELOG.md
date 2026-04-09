# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `README.md` was rewritten in a `layercache`-style hero layout with clearer package positioning, badge coverage, and navigation for Quick Start, security, integrations, and API docs.
- Package metadata and installation docs now target the publishable scoped npm name `@flyingsquirrel0419/jwt-refresh`.

### Added
- `CHANGELOG.md` to track release history in a stable format.
- `docs/api.md` for the public `JwtManager` surface and option reference.
- `docs/comparison.md` to position `jwt-refresh` against lower-level JWT libraries and framework helpers.
- GitHub Actions CI workflow for `lint`, `test`, `coverage`, and `build` on Node.js 18 and 20.
- `json-summary` coverage output so coverage artifacts can be consumed by CI tooling in addition to text and lcov reports.
- Coveralls coverage upload from GitHub Actions using the generated `coverage/lcov.info` report.

### Removed
- `Jwt-plan.md` now that the implementation has been completed and the repository docs are the source of truth.

## [0.1.0] - 2026-04-09

### Added
- `JwtManager` as the main orchestration API for issuing, verifying, rotating, refreshing, revoking, and blacklisting JWT-based sessions.
- Access-token and refresh-token handling with configurable TTLs, issuer/audience support, legacy-secret verification, and typed payload propagation.
- Refresh token rotation with absolute refresh expiry, rotation revocation reasons, and per-session metadata for device-aware session handling.
- Refresh-token reuse detection that revokes every active session for the affected user and emits `token:reuse-detected` for downstream incident handling.
- Refresh race protection that distinguishes a legitimate in-flight refresh from token theft and returns retry semantics instead of forcing accidental logout.
- Cookie-aware refresh flows through `refreshHandler()` with production-ready defaults for `httpOnly`, `sameSite`, path scoping, and secure-cookie support.
- Access-token blacklisting and immediate rejection of still-valid access tokens after logout, password reset, or other sensitive events.
- Session revocation helpers for current-session logout, single-session revocation, and revoke-all-sessions flows.
- Store adapters:
  `MemoryTokenStore`, `RedisTokenStore`, `PrismaTokenStore`, and `DrizzleTokenStore`.
- Mutex adapters:
  `InMemoryMutex` and `RedlockMutex`.
- Framework integrations for Express, Fastify, Next.js App Router, and NestJS.
- Example projects for complete Express, Next.js App Router, and NestJS integration paths.
- Security, architecture, contribution, and policy docs to support production adoption.
- Test coverage across integration, security, core, adapter, and integration-helper paths; the suite currently passes with **64 tests** and **99.05%** line coverage.

### Fixed
- `RedisTokenStore.getSessionsByUserId()` now reads the full user-session range correctly instead of truncating sorted-session lookup results.
- Adapter and integration branches now have dedicated regression coverage around serialization, null lookups, blacklist persistence, and request-framework edge handling.
