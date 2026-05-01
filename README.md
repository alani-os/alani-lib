# alani-lib

Shared safe wrappers, result types, error vocabulary, no_std utilities, and ergonomic APIs used by userspace and services.

| Field | Value |
|---|---|
| Status | Experimental MVK skeleton |
| Tier | MVK required |
| Owner | Core library team |
| Aliases | None |
| Architectural dependencies | `alani-abi` |

## Quick Start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

## Scope

This crate is intentionally dependency-free while `alani-abi` stabilizes. It implements no-std-friendly host-mode contracts for:

- ABI-safe `repr(C)` status, version, buffer, trace, budget, syscall frame, and syscall return structures;
- stable syscall numbers and group/name helpers for the public MVK syscall surface;
- safe user-buffer constructors from slices with reserved-bit, null-pointer, and length validation;
- stable error mapping between rich Rust errors and ABI status codes;
- trace context helpers, deterministic host-test trace IDs, structured event envelopes, and redaction policies;
- safe syscall wrapper methods over an injectable `SyscallTransport` for host tests, simulators, and future architecture shims.

## Layout

```text
src/
  abi.rs      ABI-safe shared data types and syscall constants
  error.rs    result alias and stable error/status mapping
  lib.rs      crate identity, re-exports, and module boundary
  syscall.rs  safe syscall wrappers over SyscallTransport
  trace.rs    trace context, event envelope, and redaction helpers
tests/
  smoke.rs    host-mode conformance and negative tests
```

## Specification Traceability

The first API surface is mapped to `alani-spec/docs/repositories/alani-lib.md`, Doc 08, Doc 09, Doc 10, Doc 27, Doc 28, Doc 42, and Doc 43.

Path dependencies remain out of `Cargo.toml` until `alani-abi` publishes stable public APIs, as required by the repository metadata contract.
