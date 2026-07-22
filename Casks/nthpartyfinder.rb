# frozen_string_literal: true

# Homebrew cask for nthpartyfinder (macOS). A cask — not a formula — because only casks can depend on
# other casks, which is what lets `brew install --cask nthpartyfinder` install Google Chrome too.
# Installs the signed, SLSA-provenance-tracked, embedded-NER release binary (the `binary` stanza puts
# it on PATH). All runtime dependencies install automatically: subfinder + whois (formulae) and
# Google Chrome (cask). The binary ships every data file it needs embedded, so no config is required.
# Linux users install the formula (`brew install nthpartyfinder`) instead — Homebrew has no cask
# support on Linux.
cask "nthpartyfinder" do
  arch arm: "aarch64", intel: "x86_64"

  version "1.5.0"
  sha256 arm:   "abb83da52df08f928e1b19bc6a602630e6295459e03f26398bc2148594deb98d",
         intel: "b96149d99bb1f3f374f627fc7bd9074381c5e83590dc2c57f37560c2cadf1f21"

  url "https://github.com/grcengineering/nthpartyfinder/releases/download/v#{version}/nthpartyfinder-#{arch}-apple-darwin.tgz",
      verified: "github.com/grcengineering/nthpartyfinder/"
  name "Nth Party Finder"
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering"

  depends_on formula: "subfinder"
  depends_on formula: "whois"
  depends_on cask: "google-chrome"

  binary "nthpartyfinder"

  caveats <<~EOS
    nthpartyfinder, subfinder, whois, and Google Chrome are all installed. The binary embeds its
    own data, so it works from any directory — you're ready to run `nthpartyfinder -d example.com`.
  EOS
end
