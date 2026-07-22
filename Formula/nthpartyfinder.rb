# frozen_string_literal: true

# Homebrew formula for nthpartyfinder: discover Nth-party vendor relationships via DNS
# analysis. Installs the same signed, SLSA-provenance-tracked, embedded-NER release
# artifact release.yml produces — not a from-source build. Checksums below are filled in
# by scripts/sync-homebrew-formula.sh once a release with matching tarballs actually
# exists (placeholders fail `brew install`/`brew audit` loudly, which is the correct
# failure mode for a placeholder rather than silently installing garbage).
#
# The formula dependencies `subfinder` and `whois` install automatically (both platforms), and the
# binary ships every data file it needs embedded, so no config directory is required. Google Chrome
# is NOT a formula dependency: Homebrew formulae cannot depend on a cask (`depends_on cask:` is an
# invalid formula dependency — `brew audit`/`test-bot` reject it). Chrome is powerful-but-optional
# (web-content/web-traffic/subprocessor-render discovery) and the binary degrades gracefully without
# it, so it is a caveat recommendation instead — see `caveats`.
class Nthpartyfinder < Formula
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering"
  # No explicit `version`: Homebrew scans it from the release URL's `/vX.Y.Z/` path, and an explicit
  # `version` that matches is a `brew audit` error (redundant-with-URL). sync-homebrew-formula.sh
  # bumps the version by rewriting the URL path, so the version tracks the URL automatically.
  license "MIT"

  depends_on "subfinder"
  depends_on "whois"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.5.0/nthpartyfinder-aarch64-apple-darwin.tgz"
      sha256 "abb83da52df08f928e1b19bc6a602630e6295459e03f26398bc2148594deb98d"
    else
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.5.0/nthpartyfinder-x86_64-apple-darwin.tgz"
      sha256 "b96149d99bb1f3f374f627fc7bd9074381c5e83590dc2c57f37560c2cadf1f21"
    end
  elsif OS.linux?
    url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.5.0/nthpartyfinder-x86_64-unknown-linux-gnu.tgz"
    sha256 "20e4de8f610338298e17f48820842cb17c62acbcb1f8e297d80cc012b504abc5"
  end

  def install
    bin.install "nthpartyfinder"
  end

  def caveats
    <<~EOS
      subfinder and whois were installed automatically, and all data files are embedded in the
      binary — nthpartyfinder is ready to use.

      For the browser-based discovery methods (web-content, web-traffic, and subprocessor-render),
      install Google Chrome or Chromium:
        macOS:  brew install --cask google-chrome
        Linux:  sudo apt-get install chromium   # or google-chrome-stable

      Chrome is optional: without it those phases are skipped automatically (the scan still runs and
      never hangs). It is a caveat rather than a dependency because Homebrew formulae cannot depend
      on a cask.
    EOS
  end

  test do
    assert_match "nthpartyfinder", shell_output("#{bin}/nthpartyfinder --version")
    assert_match "Usage:", shell_output("#{bin}/nthpartyfinder --help")
  end
end
