---
paths:
  - "**/*.go"
---

# Go conventions

- `gofmt` and `go vet` clean. Run `make test` before committing.
- Standard library first. New dependencies need a reason in the PR; the
  sigstore and go-containerregistry stacks are the intended ones.
- Keep packages under `internal/`; the CLI is the only public interface.
- Comments explain why, especially for security decisions and for behaviour
  that mirrors dockerd or cosign quirks. Match the surrounding comment
  density; do not narrate obvious code.
- Errors wrap with context (`fmt.Errorf("inspect image: %w", err)`); user
  facing denial text goes through `verdict.Message`.
- Use `log/slog` for operational logs (stderr) and `internal/audit` for
  decisions (stdout). Do not mix them.
- Pass `context.Context` through registry and dockerd calls. Shared
  verification runs on its own timeout, not the request's context.
