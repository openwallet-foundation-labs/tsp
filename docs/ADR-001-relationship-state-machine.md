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

---

# ADR 001: 关系状态机

## 状态
已提议

## 背景
目前的 TSP SDK 实现缺乏用于管理关系生命周期的正式状态机。这导致了几个问题：
1. **未定义的状态**：`ReverseUnidirectional`（反向单向）状态已定义但很少使用，导致节点收到关系请求时产生歧义。
2. **并发问题**：如果两个节点同时请求建立关系，双方都会处于 `Unidirectional`（单向）状态，且没有明确的解决路径。
3. **无超时机制**：在握手过程中，没有机制处理丢失的消息或无响应的对等节点。
4. **幂等性**：重复的控制消息未得到一致处理。

## 决定
我们将实现一个正式的 `RelationshipMachine`（关系状态机）来管理状态转换。

### 1. 状态机定义

状态机将基于 `RelationshipEvent`（关系事件）进行转换。

| 当前状态 | 事件 | 新状态 | 动作/备注 |
| :--- | :--- | :--- | :--- |
| `Unrelated` (无关系) | `SendRequest` (发送请求) | `Unidirectional` (单向) | 存储 `thread_id` |
| `Unrelated` (无关系) | `ReceiveRequest` (接收请求) | `ReverseUnidirectional` (反向单向) | 存储 `thread_id` |
| `Unidirectional` (单向) | `ReceiveAccept` (接收接受) | `Bidirectional` (双向) | 验证 `thread_id` 是否匹配。 |
| `ReverseUnidirectional` (反向单向) | `SendAccept` (发送接受) | `Bidirectional` (双向) | 验证 `thread_id` 是否匹配。 |
| `Bidirectional` (双向) | `SendCancel` (发送取消) | `Unrelated` (无关系) | |
| `Bidirectional` (双向) | `ReceiveCancel` (接收取消) | `Unrelated` (无关系) | |
| `Unidirectional` (单向) | `SendRequest` (发送请求) | `Unidirectional` (单向) | 幂等 (重传) |
| `Unidirectional` (单向) | `ReceiveRequest` (接收请求) | *冲突解决* | 见并发处理 |

### 2. 并发处理
当处于 `Unidirectional` 状态（已发送请求）的节点收到来自目标的 `RequestRelationship`（意味着对方也发送了请求）时：
- **比较 `thread_id`**：`thread_id` *较小*（按字典序）的请求胜出。
- **如果我的 `thread_id` < 对方的 `thread_id`**：我忽略他们的请求（或拒绝）。我期望他们接受我的请求。
- **如果我的 `thread_id` > 对方的 `thread_id`**：我接受他们的请求。我取消我的挂起请求状态并转换为 `ReverseUnidirectional`（实际上是接受他们的流程）。

### 3. 超时与重试
- **超时**：`VidContext` 将增加一个 `request_timeout` 字段。如果 `Unidirectional` 状态持续超过超时时间（例如 60秒），它将转换回 `Unrelated`。
- **重试**：在超时之前，系统可能会尝试重传。

### 4. 幂等性
- **重复请求**：如果处于 `ReverseUnidirectional` 或 `Bidirectional` 状态并收到相同的 `RequestRelationship`（相同的 `thread_id`），忽略它或重发之前的响应。
- **重复接受**：如果处于 `Bidirectional` 状态并收到具有相同 `thread_id` 的 `AcceptRelationship`，忽略它。

## 后果
- **健壮性**：在网络抖动和并发情况下，关系建立将更加可靠。
- **复杂性**：`store.rs` 的逻辑将变得更加复杂。
- **破坏性变更**：现有的手动操作状态的测试可能会失败，需要更新以遵循状态机。
