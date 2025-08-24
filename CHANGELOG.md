# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 2025-08-24
### Added
- **Optional certificate verification** for update calls:
  - `Agent.update_raw(..., verify_certificate: bool = False)` — when set to `True`, the agent verifies the certified response using BLS signatures (minsig: G1 signature, G2 public key).
  - Verification uses the official [`blst`](https://github.com/supranational/blst) Python binding. If `blst` is not installed, a descriptive error will be raised with installation instructions.
- `Certificate.verify_cert_timestamp(ingress_expiry_ns)` — validates the certificate’s `time` label against local clock with a configurable skew window.

### Changed
- `Agent.poll(...)` and `Agent.poll_and_wait(...)` accept the same `verify_certificate` flag internally to keep verification consistent while polling.

### Notes
- Default behavior remains **unchanged**: certificate verification is **off** unless `verify_certificate=True` is explicitly passed.
- For production environments, enabling certificate verification is **strongly recommended**.