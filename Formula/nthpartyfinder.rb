# frozen_string_literal: true

# Homebrew formula for nthpartyfinder: discover Nth-party vendor relationships via DNS
# analysis. Installs the same signed, SLSA-provenance-tracked, embedded-NER release
# artifact release.yml produces — not a from-source build. Checksums below are filled in
# by scripts/sync-homebrew-formula.sh once a release with matching tarballs actually
# exists (placeholders fail `brew install`/`brew audit` loudly, which is the correct
# failure mode for a placeholder rather than silently installing garbage).
class Nthpartyfinder < Formula
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering"
  version "1.4.0"
  license "MIT"

  depends_on "whois"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.4.0/nthpartyfinder-aarch64-apple-darwin.tgz"
      sha256 "2b214219aaa6a074e0d8933b1f448eacbcbb66c435bba3ce8e0f991c89640bd0"
    else
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.4.0/nthpartyfinder-x86_64-apple-darwin.tgz"
      sha256 "4a28b57cde7bb0a655fa24ab7a85e2bf1af1b0911e1e0509e1cc0245e9bde338"
    end
  elsif OS.linux?
    url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.4.0/nthpartyfinder-x86_64-unknown-linux-gnu.tgz"
    sha256 "e42a07acbd52a5f1af451cd9c39b3db05c8a9d60f81949c9c4671e7d2a653955"
  end

  def install
    bin.install "nthpartyfinder"
  end

  def caveats
    <<~EOS
      Optional dependencies for full functionality:

      For web content analysis (--enable-web-org, --enable-web-traffic-discovery):
        brew install --cask google-chrome

      For subdomain discovery (--enable-subdomain-discovery):
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    EOS
  end

  test do
    assert_match "nthpartyfinder", shell_output("#{bin}/nthpartyfinder --version")
    assert_match "Usage:", shell_output("#{bin}/nthpartyfinder --help")
  end
end
