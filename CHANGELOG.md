# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Release` workflow that builds static `x86_64` and `aarch64` musl binaries on
  every `v*.*.*` tag and attaches them to the GitHub release.
- Formatting and Clippy gates to the `Rust` workflow.
- Dependabot now also tracks the Docker base images.

### Changed

- Migrated to the Rust 2024 edition, with a minimum supported Rust version of 1.85.
- Replaced `reqwest` with `ureq` for the IP lookup, cutting the dependency tree
  from 123 crates to 68.
- Pinned the dependency versions in `Cargo.toml` instead of accepting `*`.
- The IP info cache is a `HashMap` keyed by address rather than a linearly
  scanned `Vec`.
- The builder stage of the container image is now `rust:1.98.1-alpine3.24`
  instead of an Ubuntu image that installs `rustup` on every build.
- Release assets are named per architecture: `oxipot-linux-x86_64.tar.gz` and
  `oxipot-linux-aarch64.tar.gz`.

### Fixed

- The container stored its database in `/db` instead of the `/oxipot/db` volume,
  so captured credentials were lost when the container was recreated.
- A read timeout on the telnet stream panicked the connection thread instead of
  ending the session.
- A single failed `accept()` silently stopped the listener, leaving the process
  running without serving anything.
- An intruder whose first lookup returned no country information was cached in
  the database as a permanent miss and was never looked up again.
- IP lookups now time out after three seconds instead of hanging indefinitely.
- Database and lookup errors are logged instead of being silently discarded.
- The IP info cache lock is no longer held across the IP lookup HTTP request, so
  one slow lookup no longer stalls every other connection.
- A panicking connection thread no longer poisons the IP info cache and the rate
  limiter for the rest of the process lifetime.
- The container image workflow used a `tags` filter that `workflow_run` ignores,
  so tagged releases were never published, and it published even when the `Rust`
  workflow had failed. It now triggers directly on pushes to `master` and on
  version tags.
- IPv6 loopback addresses are no longer sent to the IP lookup provider.

## [0.4.0]

Released before this changelog was introduced. See the
[release notes](https://github.com/pouriyajamshidi/oxipot/releases/tag/v0.4.0).

## [0.3.0]

Released before this changelog was introduced. See the
[release notes](https://github.com/pouriyajamshidi/oxipot/releases/tag/v0.3.0).

## [0.2.0]

Released before this changelog was introduced. See the
[release notes](https://github.com/pouriyajamshidi/oxipot/releases/tag/v0.2.0).

[Unreleased]: https://github.com/pouriyajamshidi/oxipot/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pouriyajamshidi/oxipot/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pouriyajamshidi/oxipot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pouriyajamshidi/oxipot/releases/tag/v0.2.0
