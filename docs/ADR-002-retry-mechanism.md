# ADR 002: Automatic Retry Mechanism

## Status
Proposed

## Context
Network unreliability can cause relationship requests or other control messages to be lost. Currently, if a request times out, the relationship status resets to `Unrelated`, requiring manual intervention to restart the handshake. We need an automatic retry mechanism to improve robustness.

## Decision
We will implement an **Exponential Backoff** retry strategy for relationship requests.

### 1. Retry Policy
We will introduce a `RetryPolicy` struct:
- `max_retries`: Maximum number of attempts (e.g., 3).
- `initial_delay`: Duration before first retry (e.g., 500ms).
- `multiplier`: Factor to increase delay (e.g., 1.5x).
- `max_delay`: Cap on the delay (e.g., 5s).

### 2. State Persistence (`PendingRequest`)
The `PendingRequest` struct in `store.rs` will be expanded to store the necessary data for retransmission:
- `message`: The exact `Vec<u8>` TSP message (ciphertext) generated during the initial request. This ensures cryptographic consistency (same thread_id).
- `retry_count`: Number of retries attempted so far.
- `last_attempt`: Timestamp of the last attempt.

### 3. Timeout Handling (`check_timeouts`)
The `check_timeouts` method will be updated to:
1.  Identify expired requests.
2.  Check if `retry_count < max_retries`.
3.  **If Retry**:
    - Calculate next timeout using the backoff policy.
    - Update `request_timeout`.
    - Increment `retry_count`.
    - Return the `message` and `endpoint` to the caller for transmission.
4.  **If Exhausted**:
    - Transition state to `Unrelated`.
    - Log failure.

### 4. Transport Interface
`check_timeouts` will return `Result<Vec<(Url, Vec<u8>)>, Error>`. The caller (e.g., `AsyncSecureStore` loop or main application) is responsible for actually sending these messages over the network.

## Consequences
- **Reliability**: Temporary network glitches won't kill the handshake.
- **Traffic**: Retries increase network traffic, but backoff mitigates storms.
- **Storage**: `VidContext` size increases slightly to store the cached message.
