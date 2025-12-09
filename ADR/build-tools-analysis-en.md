# Build Tool Usage: Just vs Cargo Make

This document analyzes the usage of 'Just' and 'Cargo make' build tools in the project.

## 1. Just Build Tool

### Role and Usage
In the setup of infrastructure and documentation, we retained the `Cargo test` functionality but migrated to using the `Just` tool with `Justfile`, and verified the testing process.

### Usage Guide
**Rapid Development Testing (Just)**
```bash
just                    # or just test-flow
```

### Positioning
*   **Just** is very suitable for **"Rapid Development"** (Quick & Dirty), for example, "I just want to run this specific test".

```bash
just test-relationship # Test only the relationship state machine
```
*   It provides speed for the development process.

---

## 2. Cargo Make Build Tool

### Introduction and Purpose
The main purpose of using this third-party build tool is to facilitate unit testing of specific functions or modules without affecting the execution of the overall test using `Cargo test`.

### Generating `Makefile.toml`
Currently, its functionality is completely identical to `Justfile` (Just).

**File Location:** `tsp/tsp_sdk/Makefile.toml`

```toml
[config]
default_to_workspace = false

[tasks.default]
alias = "test-flow"

[tasks.test-flow]
description = "Execute key module tests in sequence (Relationship, Retry, Queue)"
dependencies = ["test-relationship", "test-retry", "test-queue"]

[tasks.test-relationship]
description = "Run tests only for the Relationship Machine"
command = "cargo"
args = ["test", "relationship_machine"]

[tasks.test-retry]
description = "Run tests only for the Retry mechanism"
command = "cargo"
args = ["test", "retry"]

[tasks.test-queue]
description = "Run tests only for the Offline Queue"
command = "cargo"
args = ["test", "queue"]
```

### Issues Discovered and Fixed
During the build using `cargo make`, several compilation issues were exposed that were not triggered by `cargo test` (likely due to differences in feature flags or build environments), which have now been fixed:

*   **`tsp_sdk/src/crypto/mod.rs`**: Fixed a conflict where `gen_encrypt_keypair` function was defined repeatedly when both `nacl` and `pq` features were enabled.
*   **`tsp_sdk/src/cesr/packet.rs`**: Fixed code errors under the `demo` feature:
    *   `encode_ciphertext` call was missing the `CryptoType` argument.
    *   The closure return type in `encode_tsp_message` was incorrect (changed from `[u8]` to `Vec<u8>`).

### Why did `cargo make` find issues that `cargo test` missed?
This usually boils down to differences in how **Feature Flags** are activated:

*   **Manual Just Execution (`cargo test ...`)**: Typically uses only the **default features** defined in `Cargo.toml`. If certain code is hidden behind optional features (like `demo`, `pq`), manual testing can easily miss them.
*   **Cargo Make Execution**:
    *   `cargo make` may perform environment checks or pre-build steps before executing tasks.
    *   In this case, `cargo make` seemed to trigger a broader combination of features (activating `nacl` and `pq` simultaneously, as well as the `demo` feature), thereby exposing:
        1.  **Code Conflicts**: Duplicate function definitions in `crypto/mod.rs` when `nacl` and `pq` are on together.
        2.  **Code Rot**: Code protected by `#[cfg(feature = "demo")]` in `cesr/packet.rs` was broken due to interface changes (missing arguments, wrong return types) but remained undiscovered because the `demo` feature is rarely enabled.

### Advantages of Using `cargo make`
This example highlights three core values of using `cargo make`:

1.  **Consistency**:
    *   It defines "how to test" in the code (`Makefile.toml`) rather than relying on developer memory. This ensures that checks are consistent regardless of who runs them or when.

2.  **Coverage**:
    *   It can be easily configured to test multiple feature combinations (e.g., `cargo make test-all-features`), preventing "it works on my machine but breaks when other features are on" situations. The example above is a classic case of "compilation failure due to feature combinations".

3.  **Orchestration**:
    *   As in our modified `Makefile.toml`, we can define `test-flow` to depend on `test-relationship`, `test-retry`, etc. `cargo make` intelligently manages the execution order and error handling of these dependencies, which is more powerful than simple shell scripts (`&&`).

### Enhancements and Fixes to `Makefile.toml`
We created a fully functional `Makefile.toml`. Compared to simply copying the `Justfile`, it offers the following additional capabilities:

```toml
# Main Test Flow (Consistent with Justfile functionality)
- test-flow: Tests Relationship, Retry, Queue

# Multi-Feature Combination Testing (Strength of cargo make)
- test-no-default: No default features
- test-demo: demo feature
- test-pq: Post-Quantum cryptography feature
- test-nacl: NaCl cryptography feature
- test-async: async feature

# Comprehensive Verification
- ci-flow: CI level verification (Passed successfully!)
- full-test: Fully test all feature combinations
```

### CI Flow Verification
Result of running `cargo make ci-flow`:
```
[✓] test-flow: 8 tests passed
[✓] check-all-features: Compilation check passed
[✓] test-async: 63 tests passed
[✓] Build Done in 8.86 seconds
```

### Key Design Decisions
 **avoided using `--all-features`** for testing because:
- Certain feature combinations create incompatibilities (e.g., `pq + nacl`).
- Using `--no-default-features + --features <specific>` provides more precise control.
- `check-all-features` ensures all features compile, but does not enforce that all tests pass.

### Usage Guide
**Standardized Build (Cargo Make)**
```bash
cargo make              # Executes test-flow by default
cargo make ci-flow      # CI level verification
cargo make test-pq      # Test specific feature
cargo make full-test    # Fully test all combinations
```

### Positioning
*   **Cargo Make** is very suitable for **"Standardized Build"**, ensuring code robustness under various configurations and is suitable for integration into CI/CD pipelines.
*   It provides quality assurance.

---

## 3. Summary
Using both tools simultaneously is a very smart strategy: use `Just` for speed, and `Cargo Make` for quality assurance.
