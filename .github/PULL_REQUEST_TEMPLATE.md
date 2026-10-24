## What and why

<!-- One concern per PR. Link the issue if there is one. -->

## Checklist

- [ ] Based on `dev` and targeting `dev`
- [ ] `bash -n` on changed scripts; `gofmt`, `go vet`, `go test -race ./...` pass
- [ ] `tests/test_*.sh` pass (new behaviour has a test)
- [ ] Routes or error codes changed → ran `python3 tools/gen_docs.py` and committed `docs/API.md`, `docs/ERROR_CODES.md`
- [ ] User-visible change → line added to `CHANGELOG.md`
- [ ] No secrets, tokens, bundles or real IPs in code, tests or logs
