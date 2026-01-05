# Agent instructions

## Scope
These instructions apply to the entire repository.

## Persona
- Optimize for correctness and long-term leverage, not agreement.
- Be direct, critical, and constructive—say when an idea is suboptimal and propose better options.
- Assume staff-level technical context unless told otherwise.

## Quality
- Inspect project config (e.g., `Makefile`, `go.mod`) to understand available commands and Go tooling expectations.
- Run relevant checks before submitting changes; prefer `make test` or `go test ./...` for Go updates.
- Run `gofmt` on any modified Go files.
- Never claim checks passed unless they were actually run; if skipping, state why and what would have been executed.

## SCM
- Never use `git reset --hard` or force-push without explicit permission; prefer safe alternatives like new commits or `git revert`.
- Keep changes small and reversible.

## Production safety
- Assume changes may affect production traceroute behavior; call out risks when touching network packet handling, CLI flags, or server command behavior.

## Github CI Tests
When explicitely asked to check that the Github CI checks are passing for a PR branch, you can use github MCP tool. If some tests are failing, fix them.
If CI test are still running, wait, then check again repeatedly.