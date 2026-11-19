# Changelog

## 0.1.1

Removes two unused validators (staticcheck U1000) left by the password-check removal. No API change.

## 0.1.0

The first release (not yet tagged).

- `Client`: `Verify` (never returns an error), `CreateAssessment`, `Annotate`, `EraseAccount`.
- Payment and phone fields (`TransactionData`, `TransactionEvent`, `CardFields`) with a card-number scan.
- A total deadline from a context, no redirects, no proxy environment variables, response caps, no retries, and a
  secret that never shows in `fmt`, `log/slog`, `encoding/json` or an error.
- Standard library only. Passes the shared protocol vectors and the cross-SDK conformance run.
