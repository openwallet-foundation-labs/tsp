# ADR 003: Offline Message Queue

## Status
Proposed

## Context
When sending TSP messages, the transport layer (e.g., TCP, HTTP) may be unavailable, or the recipient may be offline. Currently, if a send fails, the message is lost unless the application manually handles it. We need a mechanism to queue these messages and attempt to resend them later.

## Decision
We will implement an in-memory **Offline Message Queue** within the `SecureStore`.

### 1. `MessageQueue` Structure
We will create a new module `queue.rs` with a `MessageQueue` struct.
- **Storage**: `VecDeque<QueuedMessage>`
- **`QueuedMessage`**:
    - `message`: `Vec<u8>` (The sealed TSP message)
    - `url`: `Url` (The destination)
    - `priority`: `u8` (Optional, for future use)
    - `created_at`: `Instant`

### 2. Integration with `SecureStore`
- `SecureStore` will hold a `Arc<RwLock<MessageQueue>>`.
- **Enqueue**: When a message cannot be sent (e.g., transport error), the application (or `AsyncSecureStore`) can call `store.queue_message(url, message)`.
- **Dequeue/Flush**: A method `store.process_queue()` (or similar) will be available to retrieve messages for attempting to resend.

### 3. Integration with `AsyncSecureStore`
- `AsyncSecureStore` is the active component that handles sending.
- It will check the queue periodically or upon reconnection events.
- When the queue is not empty, it will attempt to send the messages.
- If successful, the message is removed. If failed, it remains (or is moved to the back with a backoff, reusing Feature 2's logic if applicable, though Feature 2 is specific to Relationship Requests).

### 4. Persistence
For this iteration, the queue is **in-memory only**. If the application restarts, queued messages are lost. Persistence (to disk/DB) is out of scope for now but the design should allow for it later (e.g., by serializing `MessageQueue`).

## Consequences
- **Reliability**: Messages are not lost during temporary network outages.
- **Memory Usage**: Queued messages consume memory. We may need a cap on queue size.
- **Ordering**: `VecDeque` preserves FIFO order, which is generally desired.

---

# ADR 003: 离线消息队列

## 状态
已提议

## 背景
发送 TSP 消息时，传输层（例如 TCP, HTTP）可能不可用，或者接收方可能离线。目前，如果发送失败，除非应用程序手动处理，否则消息将会丢失。我们需要一种机制来排队这些消息，并稍后尝试重新发送。

## 决定
我们将在 `SecureStore` 中实现一个内存中的 **离线消息队列 (Offline Message Queue)**。

### 1. `MessageQueue` 结构
我们将创建一个新模块 `queue.rs`，其中包含 `MessageQueue` 结构体。
- **存储**: `VecDeque<QueuedMessage>`
- **`QueuedMessage`**:
    - `message`: `Vec<u8>` (密封的 TSP 消息)
    - `url`: `Url` (目的地)
    - `priority`: `u8` (可选，供将来使用)
    - `created_at`: `Instant` (创建时间)

### 2. 与 `SecureStore` 集成
- `SecureStore` 将持有一个 `Arc<RwLock<MessageQueue>>`。
- **入队**: 当消息无法发送时（例如传输错误），应用程序（或 `AsyncSecureStore`）可以调用 `store.queue_message(url, message)`。
- **出队/刷新**: 将提供一个方法 `store.process_queue()`（或类似方法）来检索消息以尝试重新发送。

### 3. 与 `AsyncSecureStore` 集成
- `AsyncSecureStore` 是处理发送的活动组件。
- 它将定期或在重连事件发生时检查队列。
- 当队列不为空时，它将尝试发送消息。
- 如果成功，消息将被移除。如果失败，它将保留（或通过退避移至队尾，如果适用，可复用 Feature 2 的逻辑，尽管 Feature 2 专门针对关系请求）。

### 4. 持久化
在本次迭代中，队列 **仅在内存中**。如果应用程序重启，排队的消息将丢失。持久化（到磁盘/数据库）暂时不在范围内，但设计应允许以后添加（例如，通过序列化 `MessageQueue`）。

## 后果
- **可靠性**: 消息不会因暂时的网络中断而丢失。
- **内存使用**: 排队的消息会消耗内存。我们可能需要限制队列大小。
- **顺序**: `VecDeque` 保持 FIFO（先进先出）顺序，这通常是期望的。
