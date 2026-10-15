## What and why

<!-- What does this change, and why is it needed? Link issues with "Fixes #123". -->

## How it was tested

- [ ] `make test`
- [ ] `test/e2e/run.sh` (required for changes to `authz`, `gate`, `verify` or `docker`)
- [ ] New or changed behaviour has a test that fails without the change

## Safety checklist

- [ ] No path that previously denied now allows without a test showing why
- [ ] Non-gated Docker API calls are still never blocked
- [ ] Docs and `CHANGELOG.md` updated for user-visible changes
