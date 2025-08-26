# Changelog

## [2.0.0] - 2025-08-26

### Added
- **Optional certificate verification**  
  - Introduced BLS12-381 certificate verification using the official [`blst`](https://github.com/supranational/blst) Python binding.  
  - New parameter `verify_certificate` in `Agent.update_raw`.  
  - When `verify_certificate=True`, update calls are verified against the IC’s certified responses.  
  - Includes full unit test coverage for verification scenarios.  

### Changed
- **Endpoint upgrade**  
  - Migrated `update_raw` calls from legacy `/api/v2/.../call` endpoint to new **BN v3 call endpoint** (`/api/v3/canister/.../call`).  
  - Implemented response adaptation and improved retry logic for more stable request handling.  
  - Enhanced the `poll` and `poll_and_wait` methods for correctness and resilience.  

- **Timeouts & error classification**  
  - Added configurable timeout handling in client calls.  
  - Improved error classification for common canister rejection codes, with more structured runtime exceptions.

### Security
- Addresses longstanding gaps in certificate validation:  
  - `update_raw` and `poll` now support certificate verification when enabled.  
  - Protects against unverified responses from boundary nodes.

### References
- [DFINITY forum: Reducing end-to-end latencies](https://forum.dfinity.org/t/reducing-end-to-end-latencies-on-the-internet-computer/34383)  
- [DFINITY forum: Boundary node roadmap](https://forum.dfinity.org/t/boundary-node-roadmap/15562/104)  
- [GitHub issue #117](https://github.com/rocklabs-io/ic-py/issues/117)  
- [GitHub issue #115](https://github.com/rocklabs-io/ic-py/issues/115)  
- [Forum discussion: Unmaintained agents & vulnerabilities](https://forum.dfinity.org/t/unmaintained-ic-agents-containing-vulnerabilities/41589)  
- [GitHub issue #109](https://github.com/rocklabs-io/ic-py/issues/109)  
- [GitHub issue #76](https://github.com/rocklabs-io/ic-py/issues/76)  