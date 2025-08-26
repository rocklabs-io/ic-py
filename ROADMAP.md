# ic-py Maintenance & Development Roadmap

**Guiding Principles:**
- Fix all known security vulnerabilities in ic-py
- Modernize and complete the Candid type system
- Maintain feature-and-schedule alignment with agent-rs long-term

---

## Milestone 1

- **Endpoint upgrade**
    - **Issue:** ic-py is still pointing at legacy endpoints and needs to switch to v3
    - **References:**
        - [Reducing end-to-end latencies on the Internet Computer](https://forum.dfinity.org/t/reducing-end-to-end-latencies-on-the-internet-computer/34383)
        - [Boundary Node Roadmap (latest v3 endpoints)](https://forum.dfinity.org/t/boundary-node-roadmap/15562/104?u=c-b-elite)
    - **Solution:** Update ic-py’s default endpoints to the latest BN v3 addresses and maintain them as the roadmap evolves

- **Timeouts & error classification**
    - **Issues:** Missing timeouts on agent calls; lack of fine-grained error categories for canister responses (e.g. exhausted cycles, missing WASM)
    - **References:** [#117](https://github.com/rocklabs-io/ic-py/issues/117) • [#115](https://github.com/rocklabs-io/ic-py/issues/115)
    - **Solution:**
        1. Implement configurable timeouts on all agent calls
        2. Introduce structured error types for common canister-level failures

---

## Milestone 2

- **IC certificate verification**
    - **Issue:** `request_status_raw` and `request_status_raw_async` do not verify certificates, allowing a malicious node to tamper with update responses
    - **References:**
        - DFINITY forum: [Unmaintained IC agents containing vulnerabilities](https://forum.dfinity.org/t/unmaintained-ic-agents-containing-vulnerabilities/41589?u=marc0olo)
        - GitHub issue [#109](https://github.com/rocklabs-io/ic-py/issues/109)
        - PR [#56](https://github.com/rocklabs-io/ic-py/pull/56/files) • issue [#76](https://github.com/rocklabs-io/ic-py/issues/76)
    - **Solution:**
        1. Mirror agent-rs’s certificate-checking logic (see [agent-rs implementation](https://github.com/dfinity/agent-rs/blob/b53d770cfd07df07b1024cfd9cc25f7ff80d1b76/ic-agent/src/agent/mod.rs#L903))
        2. Resolve Python–BLS compatibility by invoking the Rust BLS crate via FFI or another bridging approach

---

## Milestone 3

- **Candid type-system enhancements**
    - **Issue:** Missing support for the latest Candid features (e.g. composite queries, new primitives)
    - **References:**
        - [#111](https://github.com/rocklabs-io/ic-py/issues/111) • [PR #112](https://github.com/rocklabs-io/ic-py/pull/112/files) • [#63](https://github.com/rocklabs-io/ic-py/issues/63)
        - [Latest Candid spec](https://github.com/dfinity/candid)
    - **Solution:**
        1. Update ic-py’s Candid parser/generator with all missing types per the official spec
        2. Add a test suite to validate correctness against the canonical Candid reference

---

## Milestone 4

- **Dynamic HTTP provider & routing**
    - Implement latency-based, adaptive routing between boundary nodes
    - Support more flexible selection of endpoints at runtime

- **Expanded API surface**
    - High-level wrappers for ICRC-compliant ledgers (ckBTC, ckETH, ckUSDc, etc.)
    - Out-of-the-box helpers for interacting with Bitcoin, Ethereum, and other canisters

- **Ongoing alignment & optimization**
    - Keep pace with agent-rs’s feature roadmap
    - Targeted performance tuning, stricter type checks
    - Define additional milestones once Milestones 1–3 are complete

---

### Other long-standing bugs

- **Precision of returned data**
    - Issue [#107](https://github.com/rocklabs-io/ic-py/issues/107) – floating-point vs. integer handling  