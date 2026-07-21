# Security Policy

## Reporting a vulnerability

Report privately via GitHub Security Advisories:
[**Report a vulnerability**](https://github.com/grcengineering/homebrew-grcengineering/security/advisories/new).

Please do not open a public issue for a suspected compromise of this tap.

We aim to acknowledge within 3 business days.

## What belongs here vs. upstream

This repository is a Homebrew **tap** — it contains formulae that tell Homebrew
where to download already-built artifacts, and the CI that verifies them. It
does not contain the tools themselves.

| Report here | Report upstream |
|---|---|
| A formula points at the wrong artifact, an unexpected URL, or a digest that does not match what upstream published | A vulnerability in `nthpartyfinder` itself → [grcengineering/nthpartyfinder](https://github.com/grcengineering/nthpartyfinder/security) |
| A formula executes something unexpected during `brew install` | A bug in the tool's runtime behaviour |
| Our CI, signing policy, or branch protection can be bypassed | A vulnerability in Homebrew itself → [Homebrew security](https://github.com/Homebrew/brew/security) |

## Threat model

The asset being protected is the **integrity of what `brew install` places on a
user's machine**. The primary adversary is someone who obtains write access to
this repository — through a stolen credential, a compromised maintainer device,
or a malicious pull request — and changes a formula to serve a different binary.

These formulae install **prebuilt** artifacts, so this tap does not benefit from
homebrew-core's build-from-source protection. Homebrew's install-time
attestation verification does not apply either: it is gated to core taps and
bottle installs. Both gaps are load-bearing assumptions of what follows.

### Controls

- **Provenance binding.** `formula-integrity.yml` verifies every artifact against
  upstream's SLSA Build L3 provenance with `slsa-verifier`, pinned to the
  expected source repository *and* tag. A digest check alone would not catch an
  attacker who edits the `url` and `sha256` together; this does, because it
  requires a signature from upstream's builder over an artifact upstream built.
- **Source allowlist.** Formula URLs must be `https` GitHub release assets from a
  repository named in `ALLOWED_SOURCE_REPOS` in
  `scripts/verify-formula-artifacts.rb`. Adding an upstream is a reviewed change.
- **Continuous re-verification.** The same checks run weekly against already-merged
  formulae, so tampering after review — a swapped or deleted release asset, a
  re-pointed tag — is detected rather than silently served.
- **Human-only signing.** Two distinct mechanisms, not to be conflated. *Server
  side* — the authoritative one — GitHub branch protection requires signed commits
  on `main`, and a signature is valid only for a key registered to an authorised
  GitHub account. *Local side* — `.sscsb/policy/signers.toml` +
  `allowed_signers` govern `git`/sscsb-hook verification on a developer machine.
  AI agents are excluded at both layers: no AI key is registered to the GitHub
  org, and none is emitted into `allowed_signers`, so an AI signature is valid
  nowhere regardless of how the local policy file is edited.
- **Review and branch protection.** `main` requires pull requests, blocks force
  pushes and deletion, requires signed commits, and requires the integrity and
  `brew test-bot` checks to pass. `CODEOWNERS` requires owner review of
  `Formula/`, the workflows, and the verification script itself.
- **Least-privilege CI.** Every action is pinned to a full commit SHA, every job
  declares `permissions:`, and every job runs Harden-Runner.

### Known limitations

Stated plainly, because a threat model that only lists strengths is marketing:

- **Install-time verification is not possible.** All provenance checking happens
  in CI, before merge. A user running `brew install` performs only Homebrew's
  `sha256` check. If this repository and its CI were both subverted, a user
  would not detect it at install time. Homebrew offers third-party taps no hook
  to close this; see [Homebrew/brew#17019](https://github.com/Homebrew/brew/issues/17019).
- **Trust is transitive to upstream's build pipeline.** We verify that an artifact
  came from `grcengineering/nthpartyfinder`'s builder for a given tag. We do not
  independently verify what that build did.
- **Weekly re-verification is a detection control, not a prevention control.** It
  bounds exposure to at most one week, not to zero.
- **Egress from CI is monitored (`audit`), not blocked.** Tightening Harden-Runner
  to `block` with an explicit allowlist is a planned improvement.
- **Provenance binds the tarball, not the formula code.** A formula is Ruby that
  runs during `brew install`. The digest and signature prove the *downloaded
  bytes* came from upstream; they say nothing about what the surrounding `install`
  block does. CI flags high-signal RCE constructs, but that is a heuristic — the
  real control on formula code is code-owner review, not a scanner.
- **Review and signing rest on a single maintainer.** `CODEOWNERS` routes review
  to one owner, who is also the sole registered signer. That one identity is a
  single point of failure for both review and signing — the "compromised
  maintainer" adversary this model names. Adding a second independent reviewer/
  signer is the highest-value hardening still open.
- **A green CI check is not self-sufficient.** Because a pull request can edit the
  workflow that produces the integrity check, the check is only trustworthy in
  combination with branch protection and required code-owner review of
  `.github/**` and `scripts/**`. Those settings live in GitHub configuration, not
  in this tree, and cannot be verified by reading the repository alone.

## Verifying an install yourself

You do not need to trust this tap's CI. Every claim above is independently
checkable — see the *Verify it yourself* section of the
[README](README.md#verify-it-yourself).
