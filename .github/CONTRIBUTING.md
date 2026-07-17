# Contributing to Gleipnir

Thank you for your interest in contributing. Gleipnir is a post-quantum, cryptographically auditable chain-of-custody network. Security and correctness are paramount.

## Quick Start

```bash
git clone git@github.com:had-nu/gleipnir.git
cd gleipnir
make build
make test
make test-race
make lint
```

## Before You Contribute

### Developer Certificate of Origin (DCO)

All contributions must include a `Signed-off-by` trailer in the commit message,
certifying that you have the right to submit the contribution under the AGPL-3.0 license:

```
Signed-off-by: Your Name <your.email@example.com>
```

This certifies compliance with the [Developer Certificate of Origin](https://developercertificate.org/) version 1.1.

To sign off automatically, use `git commit -s`.

### Commit Signing (Recommended)

All commits should be signed with a GPG or SSH key. Configure Git:

```bash
git config --global user.signingkey <your-key-id>
git config --global commit.gpgsign true
```

### Commit Messages

- Use the imperative mood ("Fix bug" not "Fixed bug" or "Fixes bug")
- First line: concise summary (≤50 characters)
- Body: explain *what* and *why*, not *how*
- Reference issues with `#issue-number`

## Pull Request Process

1. **Open an issue first** — discuss the change before implementing, especially for new features or protocol modifications.
2. **Keep PRs focused** — one logical change per PR. Refactoring, docs, and features should be separate PRs.
3. **Write tests** — all new code must include tests. Verify with:
   ```bash
   make test
   make test-race
   ```
4. **Run lint** — ensure no linting issues:
   ```bash
   make lint
   ```
5. **Sign your commits** — every commit must be signed (`git commit -s`).
6. **Update documentation** — if changing behavior, update relevant `.md` files.
7. **Verify checklist** — fill in the PR template checklist.

### PR Review Criteria

- Correctness — does the change do what it claims?
- Security — does it introduce vulnerabilities or weaken guarantees?
- Test coverage — are edge cases covered?
- Code quality — is the code idiomatic Go? Are comments meaningful?
- Performance — are there benchmarks if performance may be impacted?

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) conventions
- Run `gofmt` before committing (integrated into `make lint`)
- Exported types and functions must have Go doc comments
- Tests use standard `testing` package with `t.Run` subtables
- Avoid unnecessary comments — code should be self-documenting

## Security Issues

**Do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Questions?

Open a [Discussion](https://github.com/had-nu/gleipnir/discussions) or email **andre_ataide@proton.me**.
