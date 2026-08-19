# frozen_string_literal: true

# Homebrew CASK for nthpartyfinder (macOS only).
#
# Why a cask exists alongside the formula: only casks may depend on other casks, and that is what
# lets a single `brew install --cask nthpartyfinder` also install Google Chrome. The formula cannot
# — Homebrew forbids a formula depending on a cask — so the formula install path relies on the
# binary's runtime browser prompt instead. Both paths work; the cask is the zero-decision one on
# macOS, and the formula is the only option on Linux (Homebrew has no cask support there).
#
# This file is the SOURCE OF TRUTH, tracked in the product repo. `scripts/sync-homebrew-formula.sh`
# fills in the version and checksums for a release and copies it into the tap. It previously lived
# only as an untracked file inside a local tap checkout, which is why v1.5.0 shipped with no cask
# published at all — nothing in CI could see it, so nothing could notice it was missing.
#
# The version and the two `sha256` values below are rewritten by the sync script; the placeholder
# checksums fail `brew install` and `brew audit` loudly, which is the correct failure mode for a
# placeholder rather than silently installing garbage.
cask "nthpartyfinder" do
  arch arm: "aarch64", intel: "x86_64"

  version "1.7.0"
  sha256 arm:   "32c5126d9cba53de91c990620b7000a5e74253baba7c90f3661475ebfe5e0a1d",
         intel: "d9011c33664f72cf9c7a0c36cd7c501371c5b9855865e39efa2c07a8bcbda6d8"

  url "https://github.com/grcengineering/nthpartyfinder/releases/download/v#{version}/nthpartyfinder-#{arch}-apple-darwin.tgz",
      verified: "github.com/grcengineering/nthpartyfinder/"
  name "Nth Party Finder"
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering/"

  # macOS-only: the artifact is a -apple-darwin binary, so `brew readall --os=all` (run by the
  # tap's test-bot) requires an explicit macOS declaration — without it the Linux simulation
  # leaves sha256 nil and the audit fails. Symbol form (`:big_sur`), not the deprecated string
  # comparison form.
  depends_on macos: :big_sur
  depends_on formula: "subfinder"
  depends_on formula: "whois"
  depends_on cask: "google-chrome"

  binary "nthpartyfinder"

  caveats <<~EOS
    nthpartyfinder, subfinder, whois, and Google Chrome are all installed. The binary embeds its
    own data, so it works from any directory — you're ready to run `nthpartyfinder -d example.com`.
  EOS
end
