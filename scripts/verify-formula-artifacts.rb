#!/usr/bin/env ruby
# frozen_string_literal: true
# rubocop:disable all
#
# `brew test-bot --only-tap-syntax` runs `brew style` (Homebrew's RuboCop) over
# EVERY Ruby file in the tap, including this one. Those cops are tuned for the
# Homebrew formula DSL — double-quoted strings, 118-char lines — and are the
# wrong ruler for a standalone 500-line supply-chain verification CLI. This file
# is not unverified: it has a behavioural gate (formula-integrity.yml runs it
# against the real release and six exploit formulae) plus a `ruby -c` syntax
# check. A tap `.rubocop.yml` Exclude does NOT work here (brew style force-lints
# tap Ruby regardless), so cops are disabled at the file level instead.

# verify-formula-artifacts — the tap's artifact-integrity gate.
#
# A Homebrew tap is a distribution channel: whoever lands a commit on `main`
# decides what `brew install` puts on a user's machine. This tap ships *prebuilt*
# binaries, so it does not get Homebrew's strongest structural defence
# (homebrew-core builds from source). And `HOMEBREW_VERIFY_ATTESTATIONS` does not
# help either — brew hard-gates attestation checking to homebrew-core
# (`formula.tap&.core_tap?` in Library/Homebrew/formula_installer.rb) and to
# bottle installs — so a third-party tap fetching a release tarball gets no
# attestation verification at install time.
#
# That leaves one place to bind these formulae to upstream's build: here, in CI,
# before a change can merge, and again weekly.
#
# ── The design lesson that shaped this file ──
#
# A formula is executable Ruby; Homebrew evaluates it, it does not pattern-match
# it. An earlier version of this script extracted `url "…"` / `sha256 "…"` with a
# line-anchored regex — and that is a text model of the formula, not the artifact
# Homebrew resolves. A malicious formula can show the scanner one benign, fully
# verifiable pair while making Homebrew fetch something else, via a backslash
# continuation, a `.sub`/interpolation transform, an `on_macos`/`on_linux` block,
# or a computed URL. So this script does NOT trust that it can see everything by
# recognising a syntax; it works deny-by-default instead:
#
#   • URL closure — EVERY http(s) URL anywhere in the formula is classified. Any
#     download-shaped URL that is not an allowlisted GitHub release asset fails,
#     whether or not it was paired with a sha256. An unseen-but-present malicious
#     URL therefore cannot hide: presence alone trips the gate.
#   • Literal-only — `url`/`sha256` must be a plain double-quoted literal, one per
#     line, nothing appended. Interpolation, `.sub`, `.dup`, method calls, and
#     line continuations are rejected, so Homebrew cannot resolve a value the
#     scanner never saw.
#   • Pair coverage — every allowlisted release URL must be matched to a verified
#     sha256 literal. A release URL with no adjacent verified digest fails.
#   • Formula-code guard — a formula is code that runs on the user's machine at
#     install time. Provenance binds the *tarball*, not the *install block*. This
#     script flags high-signal RCE constructs (eval, Base64, backticks, shell
#     spawns, IO.popen) in the formula body. This is a heuristic, not a proof:
#     formula-code trust ultimately rests on human review (CODEOWNERS) and
#     `brew audit`, which is stated plainly in SECURITY.md rather than overclaimed.
#
# For every verified (url, sha256) pair this then asserts:
#
#   1. the URL is https and an allowlisted GitHub release asset,
#   2. the digest is a real 64-hex value, not a placeholder,
#   3. the formula's `version` matches the tag in the URL,
#   4. the artifact downloads and hashes to exactly the pinned digest,
#   5. the artifact verifies against upstream's keyless signing identity, pinned
#      to the expected source repo AND tag.
#
# (5) is the load-bearing one. (4) alone only proves the formula agrees with
# itself: an attacker who edits a formula edits url and sha256 together, and the
# digest sails through. (5) fails, because the attacker cannot produce a signature
# from upstream's release workflow — running under upstream's repo at the expected
# tag — for an artifact upstream never built.
#
# TWO provenance formats are supported, because nthpartyfinder ships both across
# its release history and this tap must verify whichever a formula points at:
#
#   • cosign keyless bundle (v1.4.0+): a per-artifact `<asset>.bundle` (Sigstore
#     bundle, messageSignature), verified with `cosign verify-blob`, pinning the
#     certificate identity to the upstream repo + tag and the OIDC issuer to
#     GitHub Actions.
#   • SLSA provenance (v1.3.x and earlier): a release-wide `multiple.intoto.jsonl`,
#     verified with `slsa-verifier verify-artifact` (`--source-uri` + `--source-tag`).
#
# A bundle, if present, is preferred; otherwise SLSA. An artifact with NEITHER is
# rejected.
#
# This is a fast, platform-independent static+network gate. tests.yml adds an
# independent, authoritative per-platform check: on each of macOS-arm, macOS-intel
# and Linux, `brew fetch` resolves the artifact the way Homebrew actually will
# (so `if OS.mac?` conditionals resolve for real), and its resolved URL is
# re-checked against the allowlist and provenance. The two layers are deliberately
# redundant.
#
# Exit codes: 0 all checks passed · 1 a check failed · 2 usage/environment error.

require 'digest'
require 'json'
require 'optparse'
require 'tmpdir'
require 'uri'

# Only artifacts produced by these repositories' release pipelines may be
# distributed by this tap. Adding a formula that points somewhere else is a
# deliberate policy change and has to happen here, in a reviewed diff.
ALLOWED_SOURCE_REPOS = %w[
  grcengineering/nthpartyfinder
].freeze

# The GitHub Actions OIDC issuer. A keyless Fulcio certificate is trusted only if
# it was minted for a token from this issuer — i.e. the signature was made by a
# GitHub Actions workflow, not by some other holder of a Sigstore identity.
GHA_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'

# Filename of the SLSA provenance attached to a release by slsa-github-generator
# (nthpartyfinder v1.3.x and earlier).
SLSA_PROVENANCE_ASSET = 'multiple.intoto.jsonl'

GITHUB_RELEASE_URL = %r{
  \Ahttps://github\.com/
  (?<owner>[A-Za-z0-9._-]+)/
  (?<repo>[A-Za-z0-9._-]+)/
  releases/download/
  (?<tag>[^/]+)/
  (?<asset>[^/]+)\z
}x

# Any URL whose path ends in one of these is a package the installer would run.
# Such a URL MUST be an allowlisted GitHub release asset; anywhere else is fatal.
DOWNLOAD_EXTENSIONS = %w[.tgz .tar.gz .tar.xz .tar.bz2 .zip .gz .xz .bz2 .deb .rpm .pkg .dmg .bottle.tar.gz].freeze

# High-signal remote-code-execution constructs. A tap that installs a prebuilt
# binary has no legitimate need for any of these in a formula body; each is a
# known way to run attacker code during `brew install` on a genuine tarball.
# This is a heuristic denylist, not a soundness proof — see the header.
DANGEROUS_CODE = [
  [/\beval\b/,            'eval'],
  [/\binstance_eval\b/,   'instance_eval'],
  [/\bclass_eval\b/,      'class_eval'],
  [/\bBase64\b/,          'Base64 (commonly used to hide a payload)'],
  [/\bIO\.popen\b/,       'IO.popen'],
  [/\bOpen3\b/,           'Open3'],
  [/`[^`]*`/,             'backtick command execution'],
  [/%x[\(\{\[]/,          '%x command execution'],
  [/\bKernel\.(system|exec|spawn)\b/, 'Kernel.system/exec/spawn'],
  [/\b__send__\b/,        '__send__'],
  [%r{\bsystem\b[^\n#]*["'](/bin/)?(sh|bash|zsh)["']}, 'system() spawning a shell'],
  [/\bsystem\b[^\n#]*["']-c["']/, 'system() with -c'],
  [/\b(curl|wget)\b/,     'curl/wget in a formula body'],
].freeze

options = { download: true, provenance: true, formulae: nil }

OptionParser.new do |o|
  o.banner = 'Usage: verify-formula-artifacts.rb [options] [FORMULA...]'
  o.on('--[no-]download', 'Download artifacts and check digests (default: yes)') { |v| options[:download] = v }
  o.on('--[no-]provenance', 'Verify provenance (default: yes)') { |v| options[:provenance] = v }
  o.on('-h', '--help') { puts o; exit 0 }
end.parse!

# Homebrew loads tap formulae from Formula/, HomebrewFormula/, and the repo root.
# Discover all three so a formula cannot escape verification by being placed
# outside Formula/ (the workflow's `paths:` filter covers the same locations).
def discover_formulae
  root = File.expand_path(File.join(__dir__, '..'))
  globs = [File.join(root, 'Formula', '*.rb'),
           File.join(root, 'HomebrewFormula', '*.rb'),
           File.join(root, '*.rb')]
  globs.flat_map { |g| Dir[g] }.uniq.sort
end

options[:formulae] = ARGV.empty? ? discover_formulae : ARGV

if options[:formulae].empty?
  warn 'no formulae found'
  exit 2
end

failures = []
notes = []

def fail!(failures, formula, message)
  failures << "#{File.basename(formula)}: #{message}"
  puts "  ✗ #{message}"
end

def ok(message)
  puts "  ✓ #{message}"
end

# Non-comment lines only. Comments cannot influence what Homebrew fetches, and a
# threat-model note in a `#` comment must not trip the URL or code guards.
def code_lines(text)
  text.each_line.reject { |l| l.strip.start_with?('#') }
end

# Extract (url, sha256) pairs, enforcing that each is a PLAIN double-quoted
# literal alone on its line. A `url`/`sha256` line that is not a clean literal is
# itself a finding: it means Homebrew could resolve a value this scanner cannot,
# which is the whole class of bypass. Returns [pairs, violations].
LITERAL_URL = /\Aurl\s+"([^"\\]+)"\s*(#.*)?\z/.freeze
LITERAL_SHA = /\Asha256\s+"([0-9a-fA-F]+)"\s*(#.*)?\z/.freeze

def extract_pairs(text)
  pairs = []
  violations = []
  pending = nil
  # Skip the `livecheck do … end` block: its `url` is a version-check source
  # (often the symbol `:stable`), never an install artifact, so the literal-only
  # rule does not apply there. The whole-text URL-closure scan still covers this
  # block, so a download-shaped URL cannot hide inside it.
  skip_indent = nil

  code_lines(text).each_with_index do |line, idx|
    stripped = line.strip
    lineno = idx + 1

    if skip_indent
      skip_indent = nil if line.match?(/\A#{skip_indent}end\s*\z/)
      next
    end
    if (m = line.match(/\A(\s*)livecheck\s+do\b/))
      skip_indent = Regexp.escape(m[1])
      next
    end

    if stripped.start_with?('url')
      if (m = stripped.match(LITERAL_URL))
        pending = { url: m[1], line: lineno }
      else
        violations << "line ~#{lineno}: `url` is not a plain double-quoted literal " \
                      "(interpolation, method calls, or line continuation are not allowed): #{stripped}"
      end
    elsif stripped.start_with?('sha256')
      if (m = stripped.match(LITERAL_SHA))
        if pending
          pairs << pending.merge(sha256: m[1])
          pending = nil
        end
        # a sha256 with no preceding url is harmless (some blocks reuse), ignore
      else
        violations << "line ~#{lineno}: `sha256` is not a plain hex literal: #{stripped}"
      end
    end
  end

  pairs << pending.merge(sha256: nil) if pending
  [pairs, violations]
end

# Every http(s) URL in the formula body, classified. Deny-by-default: the caller
# fails on any download-shaped URL that is not an allowlisted GitHub release.
def scan_urls(text)
  urls = []
  code_lines(text).join.scan(%r{https?://[^\s"'`)]+}) { |u| urls << u.sub(/[.,;]+\z/, '') }
  urls.uniq
end

def download_shaped?(url)
  path = (URI.parse(url).path rescue url).downcase
  DOWNLOAD_EXTENSIONS.any? { |ext| path.end_with?(ext) } ||
    url.include?('/releases/download/')
end

def allowlisted_release?(url)
  m = GITHUB_RELEASE_URL.match(url)
  m && ALLOWED_SOURCE_REPOS.include?("#{m[:owner]}/#{m[:repo]}")
end

def declared_version(text)
  line = code_lines(text).find { |l| l.strip.match?(/\Aversion\s+"/) }
  line && line.strip[/\Aversion\s+"([^"]+)"/, 1]
end

def download(url, dest, quiet: false)
  args = ['curl', '--fail', '--silent', '--location',
          '--retry', '3', '--retry-delay', '2', '--max-time', '900',
          '-o', dest, url]
  # A required download reports why it failed; a best-effort probe (e.g. an
  # optional `.bundle`) stays silent so an expected 404 is not printed as noise.
  args << '--show-error' unless quiet
  redirect = quiet ? { out: File::NULL, err: File::NULL } : {}
  system(*args, exception: false, **redirect)
end

def tool?(name)
  # PATH-native so it is correct on every runner. (`system('command', '-v', …)`
  # execs a nonexistent `command` binary on Linux — it is a shell builtin, not an
  # executable — and would falsely report every tool missing.)
  ENV['PATH'].to_s.split(File::PATH_SEPARATOR).any? do |dir|
    File.executable?(File.join(dir, name))
  end
end

puts "verify-formula-artifacts — #{options[:formulae].length} formula(e)"
puts "  download: #{options[:download]}  provenance: #{options[:provenance]}"
puts

if options[:provenance]
  missing = %w[cosign slsa-verifier].reject { |t| tool?(t) }
  unless missing.empty?
    warn "provenance verification needs both cosign and slsa-verifier; missing: #{missing.join(', ')}."
    warn 'A tap that quietly skips provenance because a tool is absent is worse than one that stops.'
    warn 'Install the missing tool(s), or pass --no-provenance to accept a DEGRADED run that'
    warn 'explicitly does NOT check provenance.'
    exit 2
  end
end

Dir.mktmpdir('formula-verify') do |workdir|
  provenance_cache = {}

  options[:formulae].each do |formula|
    puts File.basename(formula)

    unless File.file?(formula)
      failures << "#{formula}: not a file"
      puts '  ✗ not a file'
      next
    end

    text = File.read(formula)
    version = declared_version(text)

    # ── Formula-level guards (deny-by-default), before any per-pair work ──

    # A `head` spec installs from a mutable branch, bypassing pinning entirely.
    if code_lines(text).any? { |l| l.strip.match?(/\Ahead\b/) || l.include?('head do') }
      fail!(failures, formula, 'formula declares a `head` spec — HEAD installs bypass sha256 pinning and provenance')
    end

    # URL closure: no download-shaped URL may point anywhere but an allowlisted release.
    scan_urls(text).each do |u|
      next unless download_shaped?(u)
      next if allowlisted_release?(u)
      fail!(failures, formula,
            "non-allowlisted download URL present: #{u} — every artifact this tap installs must be a " \
            'GitHub release asset from a repo in ALLOWED_SOURCE_REPOS')
    end

    # Formula-code guard: high-signal RCE constructs in the body.
    code = code_lines(text).join
    DANGEROUS_CODE.each do |re, name|
      next unless code.match?(re)
      fail!(failures, formula,
            "formula body contains #{name} — a prebuilt-binary tap installs with declarative DSL " \
            '(bin.install, …); executable code in a formula runs on the user\'s machine and is not permitted')
    end

    pairs, violations = extract_pairs(text)
    violations.each { |v| fail!(failures, formula, v) }

    if pairs.empty?
      fail!(failures, formula, 'no url/sha256 literal pairs found')
      next
    end

    # Pair coverage: every allowlisted release URL in the text must be a verified pair.
    paired = pairs.map { |p| p[:url] }
    scan_urls(text).each do |u|
      next unless allowlisted_release?(u)
      next if paired.include?(u)
      fail!(failures, formula,
            "release URL #{u} appears in the formula but is not paired with a verified sha256 literal")
    end

    pairs.each do |pair|
      url = pair[:url]
      sha = pair[:sha256]
      label = (File.basename(URI.parse(url).path) rescue url)

      unless url.start_with?('https://')
        fail!(failures, formula, "#{label}: url is not https (#{url})")
        next
      end

      m = GITHUB_RELEASE_URL.match(url)
      unless m
        fail!(failures, formula,
              "#{label}: url is not a GitHub release asset — this tap only distributes artifacts " \
              "from a GitHub release with provenance (#{url})")
        next
      end

      slug = "#{m[:owner]}/#{m[:repo]}"
      tag = m[:tag]

      unless ALLOWED_SOURCE_REPOS.include?(slug)
        fail!(failures, formula,
              "#{label}: source repo #{slug} is not in ALLOWED_SOURCE_REPOS — " \
              'adding a new upstream is a reviewed policy change')
        next
      end

      if sha.nil?
        fail!(failures, formula, "#{label}: url has no sha256")
        next
      end

      unless sha.match?(/\A[0-9a-f]{64}\z/)
        fail!(failures, formula, "#{label}: sha256 is not 64 lowercase hex digits")
        next
      end

      if sha == '0' * 64
        fail!(failures, formula,
              "#{label}: sha256 is the all-zero PLACEHOLDER — the formula does not yet point at a real " \
              "published artifact. Fill it from the actual release (#{tag}) before merging.")
        next
      end

      # version/tag agreement. `version` is a plain literal (enforced above) or
      # absent; if absent we still bind via the URL's tag, so this is a
      # consistency check, not the only tag anchor.
      if version && tag != "v#{version}" && tag != version
        fail!(failures, formula,
              "#{label}: formula declares version #{version.inspect} but the url points at tag " \
              "#{tag.inspect} — version and tag must agree")
        next
      end

      unless options[:download]
        ok "#{label}: static checks passed (download skipped)"
        next
      end

      artifact = File.join(workdir, "#{slug.tr('/', '_')}-#{tag}-#{label}")
      unless File.file?(artifact)
        unless download(url, artifact)
          fail!(failures, formula, "#{label}: download failed (#{url}) — release asset missing or unpublished")
          next
        end
      end

      actual = Digest::SHA256.file(artifact).hexdigest
      if actual != sha
        fail!(failures, formula,
              "#{label}: DIGEST MISMATCH — formula pins #{sha}, artifact hashes to #{actual}")
        next
      end
      ok "#{label}: sha256 matches pinned digest"

      next unless options[:provenance]

      # Prefer the per-artifact cosign bundle (v1.4.0+); fall back to the
      # release-wide SLSA provenance (v1.3.x and earlier).
      bundle = "#{artifact}.bundle"
      unless File.file?(bundle)
        download("#{url}.bundle", bundle, quiet: true) || (File.delete(bundle) if File.file?(bundle))
      end

      if File.file?(bundle) && File.size(bundle).positive?
        # cosign keyless: the certificate identity must be a workflow in the
        # expected upstream repo, minted for a GitHub Actions OIDC token, at the
        # expected tag. The workflow *filename* is not pinned (it can be renamed
        # upstream); the repo+tag binding is what an attacker cannot forge
        # without write access to upstream itself.
        id_re = "^https://github\\.com/#{Regexp.escape(slug)}/\\.github/workflows/[^@]+@refs/tags/#{Regexp.escape(tag)}$"
        verified = system('cosign', 'verify-blob', artifact,
                          '--bundle', bundle,
                          '--certificate-identity-regexp', id_re,
                          '--certificate-oidc-issuer', GHA_OIDC_ISSUER,
                          out: File::NULL, err: File::NULL, exception: false)
        if verified
          ok "#{label}: cosign keyless signature verified (#{slug} release workflow @ #{tag})"
        else
          fail!(failures, formula,
                "#{label}: COSIGN VERIFICATION FAILED — the artifact is not signed by #{slug}'s " \
                "release workflow at #{tag}")
        end
        next
      end

      slsa = provenance_cache[cache_key = "#{slug}@#{tag}"] ||= begin
        path = File.join(workdir, "#{slug.tr('/', '_')}-#{tag}-#{SLSA_PROVENANCE_ASSET}")
        prov_url = "https://github.com/#{slug}/releases/download/#{tag}/#{SLSA_PROVENANCE_ASSET}"
        download(prov_url, path, quiet: true) ? path : nil
      end

      if slsa.nil?
        fail!(failures, formula,
              "#{label}: no provenance for #{slug}@#{tag} — neither a cosign bundle (#{label}.bundle) " \
              "nor SLSA provenance (#{SLSA_PROVENANCE_ASSET}) is published. This tap will not distribute " \
              'an artifact it cannot trace to a build.')
        next
      end

      verified = system('slsa-verifier', 'verify-artifact', artifact,
                        '--provenance-path', slsa,
                        '--source-uri', "github.com/#{slug}",
                        '--source-tag', tag,
                        out: File::NULL, err: File::NULL, exception: false)

      if verified
        ok "#{label}: SLSA provenance verified against github.com/#{slug}@#{tag}"
      else
        fail!(failures, formula,
              "#{label}: SLSA VERIFICATION FAILED against github.com/#{slug}@#{tag} — " \
              'the pinned artifact is not one upstream\'s builder produced for this tag')
      end
    end

    puts
  end
end

notes << 'provenance verification was skipped (--no-provenance): this run does NOT prove artifact origin' unless options[:provenance]
notes << 'downloads were skipped (--no-download): digests were NOT checked against real artifacts' unless options[:download]
notes.each { |n| puts "NOTE: #{n}" }
puts

if failures.empty?
  suffix = options[:provenance] ? ' and verified against upstream provenance' : ''
  puts "PASS — every formula artifact matched its pinned digest#{suffix}."
  exit 0
end

puts "FAIL — #{failures.length} problem(s):"
failures.each { |f| puts "  - #{f}" }
exit 1
