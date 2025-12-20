# ADR 001: Relationship State Machine

## Status
Proposed

## Context
The current TSP SDK implementation lacks a formal state machine for managing relationship lifecycles. This leads to several issues:
1.  **Undefined States**: The `ReverseUnidirectional` status is defined but rarely used, leading to ambiguity when a node receives a relationship request.
2.  **Concurrency Issues**: If two nodes request a relationship with each other simultaneously, both end up in a `Unidirectional` state, with no clear resolution path.
3.  **No Timeouts**: There is no mechanism to handle lost messages or unresponsive peers during the handshake process.
4.  **Idempotency**: Duplicate control messages are not handled consistently.

## Decision
We will implement a formal `RelationshipMachine` to govern state transitions.

### 1. State Machine Definition

The state machine will transition based on `RelationshipEvent`s.

| Current State | Event | New State | Action/Notes |
| :--- | :--- | :--- | :--- |
| `Unrelated` | `SendRequest` | `Unidirectional` | Store `thread_id` |
| `Unrelated` | `ReceiveRequest` | `ReverseUnidirectional` | Store `thread_id` |
| `Unidirectional` | `ReceiveAccept` | `Bidirectional` | Verify `thread_id` matches. |
| `ReverseUnidirectional` | `SendAccept` | `Bidirectional` | Verify `thread_id` matches. |
| `Bidirectional` | `SendCancel` | `Unrelated` | |
| `Bidirectional` | `ReceiveCancel` | `Unrelated` | |
| `Unidirectional` | `SendRequest` | `Unidirectional` | Idempotent (retransmission) |
| `Unidirectional` | `ReceiveRequest` | *Conflict Resolution* | See Concurrency Handling |

### 2. Concurrency Handling
When a node in `Unidirectional` state (sent a request) receives a `RequestRelationship` from the target (meaning they also sent a request):
- **Compare `thread_id`s**: The request with the *lower* `thread_id` (lexicographically) wins.
- **If my `thread_id` < their `thread_id`**: I ignore their request (or reject it). I expect them to accept my request.
- **If my `thread_id` > their `thread_id`**: I accept their request. I cancel my pending request state and transition to `ReverseUnidirectional` (effectively accepting their flow).

### 3. Timeout & Retry
- **Timeout**: A `request_timeout` field will be added to `VidContext`. If a `Unidirectional` state persists beyond the timeout (e.g., 60s), it transitions back to `Unrelated`.
- **Retry**: Before timing out, the system may attempt retransmissions.

### 4. Idempotency
- **Duplicate Request**: If in `ReverseUnidirectional` or `Bidirectional` and receive the same `RequestRelationship` (same `thread_id`), ignore it or resend the previous response.
- **Duplicate Accept**: If in `Bidirectional` and receive `AcceptRelationship` with the same `thread_id`, ignore it.

## Consequences
- **Robustness**: Relationship establishment will be reliable under network jitter and concurrency.
- **Complexity**: The `store.rs` logic will become more complex.
- **Breaking Changes**: Existing tests that manually manipulate state might fail and need updating to respect the state machine.
