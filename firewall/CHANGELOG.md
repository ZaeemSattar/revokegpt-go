# Changelog

## 0.1.1

Removes two unused validators (staticcheck U1000) left by the password-check removal. No API change.

## Unreleased

- Bundle kill switch: an optional boolean `disabled`; when true every request passes through untouched (no rules, cookies, challenge, `X-RG-Sig` or verify call).
- Opt-in signed `X-RG-Sig` header (bundle `sigHeader` plus the new `Config.SigSecret` option), matching the reference.

## 0.1.0

- First release under the MIT licence. Hostname canonicalization and matching are the core module's public `hostname`
  package (`github.com/ZaeemSattar/revokegpt-go/hostname`) instead of copies; the module requires the core module
  and declares `go 1.26`.
