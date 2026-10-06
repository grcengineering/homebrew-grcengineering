# homebrew-grcengineering

[![brew test-bot](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/tests.yml/badge.svg)](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/tests.yml)
[![Formula Integrity](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/formula-integrity.yml/badge.svg)](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/formula-integrity.yml)
[![CodeQL](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/codeql.yml/badge.svg)](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/codeql.yml)
[![Secret Scan](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/secrets-scan.yml/badge.svg)](https://github.com/grcengineering/homebrew-grcengineering/actions/workflows/secrets-scan.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/grcengineering/homebrew-grcengineering/badge)](https://securityscorecards.dev/viewer/?uri=github.com/grcengineering/homebrew-grcengineering)

Homebrew tap for [GRC Engineering](https://grc.engineering) open-source tools.

## Install

```sh
brew install grcengineering/grcengineering/nthpartyfinder
```

The fully-qualified form is deliberate. Since Homebrew 6.0.0, third-party taps
are not loaded until you trust them, and installing by fully-qualified name
trusts *that one formula* rather than the whole tap — the tightest blast radius
Homebrew offers, and what Homebrew itself recommends. If you'd rather trust the
tap wholesale:

```sh
brew tap grcengineering/grcengineering
brew install nthpartyfinder
```

## Formulas

- [`nthpartyfinder`](Formula/nthpartyfinder.rb) — discover Nth-party vendor relationships via DNS analysis · [source](https://github.com/grcengineering/nthpartyfinder)

## Security

A tap is a distribution channel, not a library. Whoever lands a commit here
decides what `brew install` puts on your machine, and these formulae install
**prebuilt** binaries — so this tap does not get homebrew-core's strongest
structural defence, which is building everything from source.

Two things follow from that, and they shape everything below.

**Homebrew will not verify these artifacts for you.** `HOMEBREW_VERIFY_ATTESTATIONS`
is hard-gated to core taps and to bottle installs
([`formula_installer.rb`](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/formula_installer.rb)),
so a third-party tap fetching a release tarball gets no attestation check at
install time. There is currently no formula DSL to opt in.

**A `sha256` alone proves less than it looks like it proves.** An attacker who
can edit a formula edits the `url` and the `sha256` together, and the digest
check agrees with itself perfectly. Pinning is necessary; it is not sufficient.

So the verification happens here, in CI, before a change can merge — and again
every week afterward. Two things it verifies, and one it deliberately does not,
stated plainly so the guarantee isn't misread.

### What is enforced

| Control | What it actually does |
|---|---|
| **Provenance binding** | Each downloaded artifact is verified against upstream's keyless signing identity — a cosign Sigstore bundle (nthpartyfinder v1.4.0+) or SLSA provenance (v1.3.x and earlier) — pinned to the expected source repo **and** tag. This is the check an attacker cannot satisfy: it needs a signature from upstream's release workflow, under upstream's repo at the expected tag, for an artifact upstream never built. |
| **Artifact integrity** | Every artifact is downloaded and its digest checked against the formula's pinned `sha256`. |
| **URL closure (deny-by-default)** | *Every* URL in a formula is classified, not just the ones a parser recognises. Any download-shaped URL that isn't an allowlisted GitHub release asset fails — so a malicious URL cannot hide in an `on_macos` block, a line continuation, or an unscanned corner. Its mere presence trips the gate. |
| **Literal-only url/sha** | `url` and `sha256` must be plain string literals. Interpolation, `.sub`, and computed values are rejected, so Homebrew cannot resolve a value the verifier never saw. |
| **Source allowlist** | A release URL must come from a repo named in `ALLOWED_SOURCE_REPOS`. Adding an upstream is a reviewed change. |
| **Version/tag agreement** | A formula's `version` must match the tag its URL points at. |
| **No `head` specs** | Rejected. A `head` install pulls a mutable branch and bypasses pinning and provenance. |
| **Formula-code guard** | Provenance binds the *tarball*, not the formula code that runs during `brew install`. CI flags high-signal RCE constructs (`eval`, `Base64`, backticks, shell spawns) in a formula body — a prebuilt-binary tap installs with declarative DSL (`bin.install`). This is a heuristic, not a proof; formula-code safety ultimately rests on human review (below), which is why `Formula/**` changes require a code owner. |
| **Weekly re-verification** | Merged formulae are re-checked on a schedule, so an asset swapped or re-pointed *after* review is caught. This is detection (≤1 week exposure), not prevention. |
| **Human-only signing** | Protected-branch commits require a hardware-backed human signature. No AI key is registered, so an AI signature cannot be valid here. |
| **Formula correctness** | `brew test-bot` runs `brew style` and `brew audit`, and builds/tests changed formulae on PRs across macOS x86_64, macOS arm64, and Linux — an authoritative per-platform fetch that resolves the artifact the way Homebrew actually will. |
| **Everything else** | SHA-pinned actions with least-privilege `permissions:`, Harden-Runner on every job, TruffleHog + Gitleaks, OpenGrep SAST (extended to Ruby), CodeQL, OpenSSF Scorecard, Dependabot for the actions the workflows call. |

**What it does not do:** none of the above proves a formula's install code is
*safe* — provenance and digests are about the tarball's bytes, not what the
Ruby around them does. That gap is closed by review, not by a scanner: see
[SECURITY.md](SECURITY.md) for the honest threat model, including the controls
that live in GitHub settings (branch protection, required review) rather than in
this tree.

### Verify it yourself

Nothing above asks you to take this repository's word for it:

```sh
# What the formula claims:
grep -A1 'url ' Formula/nthpartyfinder.rb

# What upstream actually published and signed (v1.4.0+, cosign keyless):
gh release download vX.Y.Z --repo grcengineering/nthpartyfinder \
  --pattern 'nthpartyfinder-aarch64-apple-darwin.tgz*'

cosign verify-blob nthpartyfinder-aarch64-apple-darwin.tgz \
  --bundle nthpartyfinder-aarch64-apple-darwin.tgz.bundle \
  --certificate-identity-regexp \
    '^https://github\.com/grcengineering/nthpartyfinder/\.github/workflows/[^@]+@refs/tags/vX\.Y\.Z$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Older releases (v1.3.x) shipped SLSA provenance instead:
#   slsa-verifier verify-artifact <asset> --provenance-path multiple.intoto.jsonl \
#     --source-uri github.com/grcengineering/nthpartyfinder --source-tag vX.Y.Z
```

Or run the tap's own gate, which does exactly that for every formula and every
platform:

```sh
ruby scripts/verify-formula-artifacts.rb
```

## Maintaining

Formulae are kept in sync with each project's own releases — see each project's
`RELEASING.md` / `scripts/sync-homebrew-formula.sh`.

A formula bump is a two-line diff: a `url` and a `sha256`. That is exactly the
diff an attacker wants merged, and exactly the diff that looks most boring to a
reviewer. Treat every bump as a release:

- Bumps go through a pull request. `main` blocks direct pushes and force-pushes,
  and requires code-owner review — including of `.github/**` and `scripts/**`, so
  the verification cannot be quietly weakened in the same PR it is meant to gate.
- Auto-merge stays **off**. A bot may open a bump PR; a human merges it.
- `formula-integrity.yml` re-checks the digest and provenance mechanically on the
  PR. Treat a green check as necessary, not sufficient: because a PR can also edit
  the workflow that produces that check, the check is only trustworthy alongside
  the branch-protection and code-owner rules above. Confirm a bump's digest
  against the real release artifact yourself; the green check is a second pair of
  eyes, not a substitute for the first.

This repo's supply-chain baseline is managed by
[`sscsb`](https://github.com/p4gs/sscs-bootstrapper) (`.sscsb/`). Controls that
cannot mean anything for a tap are switched **off** rather than left on and
hollow: there is no dependency tree here, so SBOM generation, vulnerability
scanning, and package-trust are disabled by design. The formulae's pinned
artifacts are this repo's real dependency surface, and `formula-integrity.yml`
is what guards it. Two notes for anyone re-running the bootstrapper:

- `sscsb init` will recreate `.github/workflows/deploy-gate.yml` (the generic
  artifact of the `provenance-verify` control). It does not apply to a tap —
  delete it. `formula-integrity.yml` is this repo's implementation of that control.
- `.sscsb/rules/sscsb-default.yaml` is locally extended to scan `*.rb`. The stock
  ruleset does not, which would leave this repo's only source language unscanned
  by its own highest-severity rule.

Report a security issue via [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Each tool installed by this tap carries its own license.
