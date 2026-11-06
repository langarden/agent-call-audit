# Contributing

Thanks for considering contributing to **agent-call-audit**.

## Ground rules

- **Fail-closed first**: when in doubt, deny. Never introduce a code path that fails open.
- **No new runtime dependencies**: the package is dependency-free by design.
- **De-identified**: commits, code and docs must not contain personal identifiers,
  employer names or private data. Run a de-identification scan before submitting.
- **Tests**: every change must keep `python -m unittest discover -s tests -t . -v` green (23 tests).

## Process

1. Fork / branch from `main`.
2. Make your change; add tests for any new invariant (extend the table in `README.md`).
3. Run the test suite locally.
4. Open a Pull Request describing which invariant you touched and why.

## Reporting issues

Use the **Issues** tab. Include a minimal repro, the expected vs actual verdict, and the
rule file used (redact anything personal). Security issues: see `SECURITY.md`.
