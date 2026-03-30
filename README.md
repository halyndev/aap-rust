# aap-protocol — Rust SDK

**Agent Accountability Protocol · Rust · ed25519-dalek**

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![tests](https://img.shields.io/badge/tests-22%2F22-brightgreen)](https://github.com/halyndev/aap-rust)

```toml
[dependencies]
aap-protocol = "0.1"
```

```rust
use aap_protocol::{KeyPair, Identity, Authorization, Level, AuditChain, AuditResult};

let supervisor = KeyPair::generate();
let agent      = KeyPair::generate();

let identity = Identity::new(
    "aap://acme/worker/bot@1.0.0",
    vec!["write:files".into()],
    &agent, &supervisor, "did:key:z6Mk",
)?;

let auth = Authorization::new(
    &identity.id, Level::Supervised,
    vec!["write:files".into()],
    false, &supervisor, "did:key:z6Mk",
)?;

// Physical World Rule — Level 4 on physical node → PhysicalWorldViolation
let result = Authorization::new(
    "aap://factory/robot/arm@1.0.0", Level::Autonomous,
    vec!["move:arm".into()], true, &supervisor, "did:key:z6Mk",
);
assert!(result.is_err()); // AAP-003
```

```bash
cargo test   # 22 integration tests + 2 doctests
cargo run --example quickstart
```

**[AAP Spec](https://aap-protocol.dev) · [NRP](https://nrprotocol.dev) · [Halyn](https://halyn.dev)**

License: MIT
