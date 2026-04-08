# Contributing

Thanks for contributing to `jwt-refresh`.

## Development workflow

1. Install dependencies with `npm install`.
2. Run tests with `npm test`.
3. Build the package with `npm run build`.
4. Keep behavior changes covered by tests.

## Pull request expectations

- Keep the scope narrow.
- Add or update tests for behavior changes.
- Update docs when the public API changes.
- Do not merge generated files that do not belong in the repo.

## Coding guidelines

- Prefer small, composable changes over broad rewrites.
- Treat refresh, revocation, and replay paths as security-sensitive code.
- Favor explicit errors over silent fallbacks.

## Reporting bugs

Open an issue with:

- the version you are using
- your runtime and framework
- a minimal reproduction
- whether the issue affects rotation, blacklisting, or request middleware
