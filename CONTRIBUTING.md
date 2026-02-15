# Contributing to Agent Passport Standard (APS)

## Issues

- Use GitHub issues to report bugs, spec ambiguity, or implementation mismatches.
- Include:
  - affected artifact (Passport, Receipt, Envelope)
  - sample JSON payload
  - expected vs actual behavior

## Pull requests

- Keep PRs focused and small.
- Add/adjust tests for any behavioral change.
- Include schema updates and implementation updates together when relevant.
- Ensure `go test ./...` and `go test ./conformance` are passing.
- Use clear commit messages following `feat(scope): summary` style.

## RFC process

For breaking or versioned changes:

1. Open an issue titled `RFC:` with problem statement and proposed solution.
2. Add examples of producer/consumer impact.
3. Add at least one maintainer and one ecosystem reviewer.
4. Reach explicit consent from reviewers before merging.
5. Tag implementation PRs with related RFC number once approved.
