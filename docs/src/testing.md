# Testing Guide

This document describes the testing strategy, infrastructure, and best practices for the TSP SDK project.

## Testing Philosophy

The TSP SDK follows a comprehensive testing approach with multiple layers:

- **Unit Tests**: Test individual functions and modules in isolation
- **Integration Tests**: Test interactions between components
- **End-to-End Tests**: Test complete workflows including CLI and language bindings
- **Fuzz Tests**: Test protocol robustness with malformed/random inputs
- **Property-Based Tests**: Test invariants across many generated inputs

Our testing strategy aims to:
1. Ensure protocol correctness and security
2. Prevent regressions in critical functionality
3. Document expected behavior through tests
4. Enable confident refactoring and improvements
5. Support automated reviews and validation

## Test Organization

### Unit Tests

Unit tests are co-located with the code they test using Rust's built-in test framework:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name() {
        // Test implementation
    }
}
```

**Location**: Within source files at `tsp_sdk/src/**/*.rs`

**When to use**: Testing individual functions, data structures, or small units of logic

### Integration Tests

Integration tests verify interactions between components and are located in dedicated test directories:

- `tsp_sdk/src/test.rs`: Core SDK integration tests
- `examples/tests/`: CLI and end-to-end workflow tests

**When to use**: Testing message flow, protocol interactions, multi-party scenarios

### Language Binding Tests

- **Python**: `tsp_python/test.py` - Python API tests using unittest
- **JavaScript/Node**: `tsp_node/test.js` - Node.js API tests using Mocha
- **WASM**: Tested via wasm-pack in CI

### Fuzz Tests

Fuzzing tests are in `fuzz/fuzz_targets/`:
- `payload_encode_decode.rs`: Test CESR encoding/decoding round-trips
- `payload_decode_garbage.rs`: Test decoder robustness against invalid input

## Running Tests

### Basic Test Commands

```bash
# Run all tests in workspace
cargo test

# Run tests for specific package
cargo test -p tsp_sdk

# Run a specific test
cargo test test_direct_mode

# Run tests with output visible
cargo test -- --nocapture

# Run tests with multiple threads
cargo test -- --test-threads=4
```

### Feature-Specific Testing

The SDK has multiple features that need testing:

```bash
# Test with default features (async, nacl)
cargo test

# Test without default features
cargo test --no-default-features

# Test with specific features
cargo test --features "pq"
cargo test --features "nacl"

# Test all feature combinations (done in CI)
cargo test --features "nacl"
cargo test --features ""
```

### Async Tests

Tests using async functions require the `tokio::test` attribute:

```rust
#[tokio::test]
async fn test_async_function() {
    // Async test code
}
```

Some tests require serialization to avoid conflicts (e.g., tests using the same TCP port):

```rust
#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_using_network() {
    // Test code
}
```

### CLI Tests

CLI tests are in `examples/tests/cli_tests.rs` and use `assert_cmd`:

```bash
# Run CLI tests
cargo test -p examples --test cli_tests

# Run specific CLI test
cargo test -p examples test_send_command_unverified_receiver
```

### Language Binding Tests

```bash
# Python tests
cd tsp_python
maturin develop
python3 test.py

# Node.js tests
cd tsp_javascript
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --target nodejs .
cd ../tsp_node
npm install
npm test

# WASM browser tests
cd tsp_sdk
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack test --node -- \
  -p tsp_sdk --no-default-features --features "resolve"
```

### Fuzz Tests

```bash
# Install cargo-fuzz (requires nightly)
cargo install cargo-fuzz

# Build fuzz targets
cargo fuzz build

# Run a fuzz target for 60 seconds
cargo fuzz run payload_encode_decode -- -max_total_time=60

# List all fuzz targets
cargo fuzz list
```

## Writing Tests

### Test Naming Conventions

- Use descriptive names: `test_<what>_<scenario>_<expected_result>`
- Good: `test_send_message_unverified_receiver_fails`
- Avoid: `test1`, `test_foo`, `test_thing`

### Test Structure

Follow the Arrange-Act-Assert pattern:

```rust
#[test]
fn test_seal_message_encrypts_content() {
    // Arrange: Set up test data
    let sender = create_test_vid();
    let receiver = create_test_vid();
    let plaintext = b"hello world";

    // Act: Execute the operation
    let sealed = seal(&sender, &receiver, None, Payload::Content(plaintext)).unwrap();

    // Assert: Verify expectations
    assert!(!sealed.is_empty());
    assert_ne!(&sealed[..], plaintext); // Should be encrypted
}
```

### Test Data Management

Test data is stored in `examples/test/`:
- `alice/piv.json`: Test VID for Alice
- `bob/piv.json`: Test VID for Bob
- `localhost.pem`, `localhost-key.pem`: TLS certificates for local testing

**Loading test VIDs**:

```rust
let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
    .await
    .unwrap();
```

### Common Test Utilities

Use the test utilities module for common operations:

```rust
#[cfg(test)]
use crate::test_utils::*;

#[test]
fn test_with_utilities() {
    let (alice, bob) = create_test_vid_pair();
    let store = create_test_store();
    // ... test code
}
```

### Testing Error Cases

Always test both success and failure paths:

```rust
#[test]
fn test_open_message_with_wrong_receiver_fails() {
    let sender = create_test_vid();
    let receiver = create_test_vid();
    let wrong_receiver = create_test_vid();

    let message = seal(&sender, &receiver, None, Payload::Content(b"test")).unwrap();

    let result = open(&wrong_receiver, &sender, &mut message.clone());
    assert!(matches!(result, Err(CryptoError::UnexpectedRecipient)));
}
```

### Async Test Patterns

For tests requiring message passing or network operations:

```rust
#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_bidirectional_messaging() {
    let alice_db = AsyncSecureStore::new();
    let bob_db = AsyncSecureStore::new();

    // Set up alice and bob...

    // Use thread::scope for concurrent operations
    thread::scope(|s| {
        s.spawn(|| {
            // Sender thread
        });
        s.spawn(|| {
            // Receiver thread
        });
    });
}
```

### Cleanup in Tests

Tests should clean up after themselves:

```rust
#[test]
fn test_with_cleanup() {
    let temp_file = "test_wallet.sqlite";

    // Test code using temp_file...

    // Cleanup
    let _ = std::fs::remove_file(temp_file);
}
```

For CLI tests, use the `clean_wallet()` helper and `serial_test::serial(clean_wallet)`.

## Code Coverage

### Running Coverage Locally

We use `cargo-llvm-cov` for code coverage:

```bash
# Install cargo-llvm-cov
cargo install cargo-llvm-cov

# Generate coverage report
cargo llvm-cov --all-features --workspace --html

# Generate lcov format for tooling
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info

# Run coverage and open HTML report
cargo llvm-cov --all-features --workspace --html --open
```

Alternatively, use the provided script:

```bash
# Run coverage with default settings
./scripts/coverage.sh

# Run coverage for specific package
./scripts/coverage.sh --package tsp_sdk
```

### Coverage in CI

Coverage is automatically measured in CI on every pull request. Reports are uploaded to coverage tracking services and commented on PRs.

### Coverage Targets

We aim for these coverage levels:

- **Cryptographic code** (`crypto/`): >95%
- **Protocol implementation** (`cesr/`, core message handling): >90%
- **Transport layers** (`transport/`): >80%
- **VID implementations** (`vid/`): >85%
- **Overall project**: >80%

### Interpreting Coverage

Coverage metrics show:
- **Line coverage**: % of lines executed
- **Branch coverage**: % of conditional branches taken
- **Function coverage**: % of functions called

Focus on meaningful coverage:
- ✅ DO cover error paths and edge cases
- ✅ DO cover security-critical code paths
- ❌ DON'T write tests just to hit coverage numbers
- ❌ DON'T test trivial getters/setters exhaustively

## Specialized Testing

### Property-Based Testing

Property-based tests verify invariants across many generated inputs:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encode_decode_roundtrip(data: Vec<u8>) {
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        prop_assert_eq!(decoded, data);
    }
}
```

**Good candidates for property-based testing**:
- Encoding/decoding round-trips
- Cryptographic properties (signature verification)
- Message serialization/deserialization
- VID validation rules

### Fuzz Testing

Fuzz tests discover edge cases and security vulnerabilities by testing with random/mutated inputs.

**Adding a new fuzz target**:

1. Create `fuzz/fuzz_targets/my_target.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use tsp_sdk::cesr::decode_envelope;

fuzz_target!(|data: &[u8]| {
    let _ = decode_envelope(data);
});
```

2. Add to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "my_target"
path = "fuzz_targets/my_target.rs"
test = false
doc = false
bench = false
```

3. Run the fuzzer:

```bash
cargo fuzz run my_target
```

### Performance Testing

Benchmarks are in `docs/src/benchmark.md` and can be run with:

```bash
# Run a specific benchmark
cargo run --example benchmark

# Run with specific features
cargo run --example benchmark --features "pq"
```

For automated performance regression testing, we use criterion (to be added):

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_seal_message(c: &mut Criterion) {
    let sender = create_test_vid();
    let receiver = create_test_vid();
    let data = b"test message";

    c.bench_function("seal_message", |b| {
        b.iter(|| seal(&sender, &receiver, None, Payload::Content(data)));
    });
}

criterion_group!(benches, bench_seal_message);
criterion_main!(benches);
```

### Cross-Platform Testing

The CI tests on multiple platforms:
- **Linux**: x86_64, armv7, aarch64 (GNU and musl)
- **WASM**: wasm32-unknown-unknown target
- **Python**: Python 3.10+
- **Node.js**: Node 20+

To test cross-platform locally:

```bash
# Test WASM compilation
cargo build --target wasm32-unknown-unknown --no-default-features --features "resolve"

# Test with different feature combinations
cargo test --no-default-features
cargo test --features "pq"
```

## CI/CD Integration

### GitHub Actions Workflows

Tests run automatically on:
- Every push to `main`
- Every pull request
- Manual workflow dispatch

Workflows in `.github/workflows/`:

- `check.yml`: Main test suite
  - Clippy linting
  - Format checking
  - Unit and integration tests (multiple feature combinations)
  - Python bindings test
  - Node.js bindings test
  - WASM test
  - Fuzz test smoke testing
  - Documentation building

- `build.yml`: Build artifacts for multiple platforms

### Test Artifacts

Failed tests generate artifacts:
- Fuzz crashes: `fuzz/artifacts/`
- Test logs: Available in CI job outputs

### Test Performance

Monitor test execution time:
- Unit tests should complete in <30 seconds
- Integration tests should complete in <2 minutes
- Full CI suite should complete in <15 minutes

Slow tests should use `#[ignore]` and run separately:

```rust
#[test]
#[ignore] // Run with: cargo test -- --ignored
fn slow_integration_test() {
    // Long-running test
}
```

## AI Agent Integration

### Running Tests Programmatically

Tests can be run with structured output for automated analysis:

```bash
# JSON output format
cargo test -- -Z unstable-options --format json

# Save results to file
cargo test -- --format json > test-results.json
```

### Test Metadata

Tests can include metadata for categorization:

```rust
#[test]
#[cfg_attr(feature = "test-metadata", test_metadata(
    category = "crypto",
    priority = "critical",
    tags = ["encryption", "security"]
))]
fn test_encryption_security() {
    // Test code
}
```

### Automated Review Criteria

AI agents should verify:
1. **All tests pass**: Exit code 0
2. **No ignored tests without reason**: Check for `#[ignore]` without comments
3. **Coverage maintained**: Coverage doesn't decrease
4. **New code has tests**: New functions have corresponding tests
5. **Tests follow naming conventions**: Descriptive test names
6. **Error paths tested**: Both success and failure cases covered

### Test Discovery

List all tests:

```bash
# List all test names
cargo test -- --list

# Count total tests
cargo test -- --list | grep -c "::"
```

### Validation Scripts

Run validation scripts before committing:

```bash
# Run all checks (format, lint, test)
./scripts/validate.sh

# Quick validation (no integration tests)
./scripts/validate.sh --quick
```

## Best Practices

### DO:
- ✅ Write tests for bug fixes (regression tests)
- ✅ Test both success and error paths
- ✅ Use descriptive test names
- ✅ Keep tests focused and independent
- ✅ Clean up resources (files, ports, etc.)
- ✅ Use test utilities for common setup
- ✅ Test security-critical code thoroughly
- ✅ Document complex test scenarios
- ✅ Use `serial_test` for tests that can't run in parallel

### DON'T:
- ❌ Write flaky tests that sometimes fail
- ❌ Test implementation details (test behavior)
- ❌ Make tests depend on each other
- ❌ Leave commented-out test code
- ❌ Ignore failing tests without investigation
- ❌ Write overly complex tests
- ❌ Skip error handling in tests
- ❌ Use hardcoded timing/sleeps (use proper synchronization)

## Troubleshooting

### Common Issues

**"Address already in use" errors**:
- Use `#[serial_test::serial(tcp)]` for network tests
- Ensure cleanup runs even on test failure

**Flaky async tests**:
- Use proper synchronization instead of `sleep()`
- Check for race conditions
- Consider using `tokio::time::pause()` for time-dependent tests

**Test hangs**:
- Check for deadlocks in async code
- Verify cleanup code runs
- Use timeouts: `.timeout(Duration::from_secs(5))`

**File not found in tests**:
- Use paths relative to workspace root
- Check `examples/test/` for test data files
- Use `env!("CARGO_MANIFEST_DIR")` for package-relative paths

### Getting Help

- Check existing tests for examples
- Review test utils in `tsp_sdk/src/test_utils.rs`
- See the [Rust testing book](https://doc.rust-lang.org/book/ch11-00-testing.html)
- Ask in GitHub discussions or issues

## Future Improvements

See GitHub issues linked to [#245](https://github.com/openwallet-foundation-labs/tsp/issues/245) for planned testing infrastructure improvements:

- Code coverage reporting and tracking
- Property-based testing expansion
- Performance regression testing
- Enhanced test utilities
- Test result archival and analysis
- Improved cross-platform testing

## Summary

Good testing ensures the TSP SDK remains secure, correct, and maintainable. Follow the guidelines in this document to write effective tests that document behavior, catch regressions, and enable confident development.

**Quick checklist for contributors**:
- [ ] Tests pass locally: `cargo test`
- [ ] Tests pass with all features: `cargo test --all-features`
- [ ] New code has corresponding tests
- [ ] Error paths are tested
- [ ] Tests are documented if complex
- [ ] CI passes on pull request
