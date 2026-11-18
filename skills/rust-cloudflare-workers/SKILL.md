---
name: rust-cloudflare-workers
description: Safe Rust 2024 (#![forbid(unsafe_code)]) patterns for workers-rs Wasm, SQLite Durable Objects, and R2 conditional writes.
---

# Rust Cloudflare Workers Patterns

- **Crate Hygiene**: Every crate MUST declare `#![forbid(unsafe_code)]` and compile with `cargo clippy --all-targets -- -D warnings`.
- **Append-Only SQLite DOs**: Enforce `BEFORE UPDATE` / `BEFORE DELETE` `RAISE(ABORT, ...)` triggers on audit tables; parameterize all queries.
- **R2 Conditional Immutability**: Write immutable blobs with `If-None-Match: *` to prevent overwrite races or cache bleed.
- **Untrusted Inputs**: Validate byte length, UTF-8, and Unicode control/tag characters at ingress before deserializing.
