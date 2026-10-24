# Contributing

Thanks for helping. Hashem is an AGPL-3.0 project; by contributing you agree your work is released under the same license.

## Ground rules

- **Branch from `dev`**, open the pull request against `dev`. `main` only receives reviewed `dev → main` promotions (and hotfixes: branch from `main`, PR to `main`, then merge `main` back into `dev`).
- **One concern per commit.** Use conventional prefixes as in the history: `feat(...)`, `fix(...)`, `docs`, `test`, `refactor`, `ci`.
- **Tests first for behaviour changes.** New Go code gets a `_test.go` next to it; shell logic gets a hermetic `tests/test_*.sh`.
- **Never test against a production server.** Tests must not touch the real `/etc`, systemd or the network. Use the existing isolation hooks (`GRE_PANEL_DIR`, `GRE_FRP_DIR`, `GRE_BACKHAUL_DIR`, `GRE_SKIP_PANEL`).
- `hashem.sh` is the single source of truth for setup and tuning. The Go panel shells out to it; do not reimplement that logic in Go.

The layout, conventions and rules are in [docs/dev/DEVELOPMENT.md](docs/dev/DEVELOPMENT.md).

## Before you open a PR

```bash
bash -n hashem.sh install.sh
cd panel
gofmt -l .                     # must print nothing
go vet ./... && go build ./...
go test -race -count=1 ./...
cd .. && for t in tests/test_*.sh; do bash "$t"; done   # *_e2e / *_lab need netns: CI runs them
python3 tools/gen_docs.py      # if you touched routes or error codes
git diff --exit-code docs/API.md docs/ERROR_CODES.md
```

CI runs the same checks, plus the lab jobs and gosec. A PR with a red check will not be merged.

## Adding things

- **An API route:** register it in `panel/main.go` with `requireAuth` (and `requireCSRF` for anything that changes state), then run `python3 tools/gen_docs.py`.
- **An error code:** add it to `errCatalog` in `panel/errors.go` with an HTTP status (or `0` for log annotations), a short message and an actionable hint, then regenerate the docs.
- **A UI change:** UI script lives in `panel/app.js`, not inline in `index.html`.
- **A user-visible change:** add a line to [CHANGELOG.md](CHANGELOG.md) under the upcoming version.

## Reporting bugs and ideas

Use the issue forms. Include the version (`hashem` → System info, or `GET /api/version`), the engine and carrier, and the **error code** if the panel showed one. Redact tokens, bundles (`hsh1_…`, `bh1_…`, `gh1_…` contain the token) and public IPs you do not want shared.

**Security problems:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
