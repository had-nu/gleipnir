# Verification Checklist

This file exists because [GLEIPNIR_REMEDIATION_SPEC_II](./docs/GLEIPNIR_REMEDIATION_SPEC_II.md)
found that two of four "DONE" issues in a prior completion report were either
fabricated or shipped with security-critical defects that passing unit tests
did not catch. The checklist below is a mechanical gate — no issue is resolved
until every applicable line is confirmed against the actual repository.

---

## Gate checklist

Before closing any issue or claiming any code-change milestone:

- [ ] **Commit range exists.** The issue description links to the exact commit
      range containing the implementation and its tests. `git log <range>`
      returns the expected commits.

- [ ] **Every claimed file confirmed present.** For each file the completion
      report mentions, `git show <commit>:<path>` succeeds and the line count
      is within 20 % of the reported value. Assertions from memory are not
      accepted — only the actual file from the repository.

- [ ] **Tests exist in the same PR/commit.** The commit range contains at least
      one new or modified test file that exercises the claimed fix. The test
      must cover the adversarial case the fix was designed to prevent, not just
      the happy path.

- [ ] **CI output attached.** The PR body or linked comment contains a CI job
      URL (not a pasted terminal summary) showing `go test ./...` passing.
      For security-sensitive changes (cryptography, quorum, access control),
      `go test -race ./...` must also pass.

- [ ] **Dead-code quarantine confirmed.** If old code was kept for reference
      (e.g., `VerifyQuorumLegacy`, `SelectProposerLegacy`), confirm via `grep`
      that it is unreachable from any non-test code path. If reachable from a
      fallback-on-error path, that path must either be removed or its trigger
      condition must be demonstrably non-exploitable.

- [ ] **Verification ledger is filled.** For any issue that references a
      remediation spec with ledger entries, every entry in the spec is filled
      with real file paths, real line numbers, and real command output before
      the issue is marked done.

---

## How to apply

1. Copy this checklist into the issue or PR body.
2. Check off each line with a concrete reference (commit hash, file path, CI link).
3. If any line cannot be checked, the issue is not resolved — document the gap
   and either fix it or escalate.

This file intentionally does not define what "done" means in general — it only
defines what evidence is required to trust a "done" claim from an automated
agent or a human working under time pressure.
