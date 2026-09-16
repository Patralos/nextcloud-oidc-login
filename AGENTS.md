# Project Context

This file should be human-readable - less tokens.
Keep it concise, short bullets, no wrapping.

## Development

- `composer install`, then `composer lint` (`php-cs-fixer` on `lib/`) and `composer psalm`.
- Dummy OIDC provider setup in `DEVELOPMENT.md`.
- Checkout lives at `<nextcloud>/apps/oidc_login`.
- `../..` is usually a Nextcloud checkout.

## Git

- Version-bump commits are named `vX.X.X` and touch only `appinfo/info.xml`.
- Never force-push unless explicitly asked.

## Release Flow

- _Confirm each step with user_.
- Version lives only in `appinfo/info.xml` (`<version>`, plus `<nextcloud min/max-version>`).
- Verify version is committed (`git show HEAD:appinfo/info.xml`).
- On master: `git fetch origin`, check in sync with `origin/master`. Dirty tree OK if tag targets clean HEAD.
- Tag convention is lightweight `vX.X.X` pointing at the bump commit.
- `git tag vX.X.X`, `git push origin vX.X.X`. Check tag absent first, `ls-remote` after.
- `gh release create vX.X.X --generate-notes --verify-tag`, plus `--prerelease` for unstable.
- Publishing the GitHub release triggers `.github/workflows/release.yaml`.
