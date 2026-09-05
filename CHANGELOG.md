# Changelog

All notable changes to this project will be documented here.

## [0.2.0] - 2026-09-05

### Added

- SARIF 2.1.0 output via `--sarif` for code-scanning and CI integrations.
- Checks for credentials embedded in any configured Git remote, including non-`origin` remotes.
- Warnings for local, private-network, `.local`, and `.internal` Git remotes.
- High-confidence detection for OpenAI, Anthropic, npm, and GitLab token formats.
- Explicit reporting for tracked symbolic links and links that point outside the repository.
- CI smoke tests for both JSON and SARIF output.

### Changed

- The scanner no longer follows tracked symbolic-link targets while reading file contents.
- Generic secret-assignment detection now ignores common placeholders and template expressions while preserving warnings for suspicious concrete values.
- Git remote discovery now enumerates all configured fetch URLs rather than only `origin`.

### Fixed

- A tracked symlink could previously cause the scanner to read a file outside the repository.
- Source-code templates such as `api_key={value}` could be misclassified as concrete secret assignments.
- Credential-bearing remote URLs are now reported without echoing the credential value.

## [0.1.0] - 2026-09-05

### Added

- Public-readiness scoring for Git repositories.
- Checks for sensitive filenames, high-confidence credential patterns, personal paths, private URLs, large files, and tracked build artifacts.
- Warnings for sensitive-looking files that remain in Git history.
- Human-readable and JSON output.
- Strict mode for CI use.
