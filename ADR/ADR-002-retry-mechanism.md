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

---

# ADR 002: 自动重试机制

## 状态
已提议

## 背景
网络的不稳定性可能导致关系请求或其他控制消息丢失。目前，如果请求超时，关系状态会重置为 `Unrelated`（无关系），需要人工干预才能重新开始握手。我们需要一种自动重试机制来提高健壮性。

## 决定
我们将为关系请求实施 **指数退避 (Exponential Backoff)** 重试策略。

### 1. 重试策略 (Retry Policy)
我们将引入一个 `RetryPolicy` 结构体：
- `max_retries`：最大尝试次数（例如 3 次）。
- `initial_delay`：首次重试前的延迟时间（例如 500ms）。
- `multiplier`：每次重试后延迟增加的倍数（例如 1.5x）。
- `max_delay`：延迟时间的上限（例如 5s）。

### 2. 状态持久化 (`PendingRequest`)
`store.rs` 中的 `PendingRequest` 结构体将被扩展，以存储重传所需的数据：
- `message`：初始请求期间生成的准确 `Vec<u8>` TSP 消息（密文）。这确保了加密的一致性（相同的 `thread_id`）。
- `retry_count`：目前已尝试的重试次数。
- `last_attempt`：最后一次尝试的时间戳。

### 3. 超时处理 (`check_timeouts`)
`check_timeouts` 方法将更新为：
1. 识别过期的请求。
2. 检查是否 `retry_count < max_retries`。
3. **如果重试**：
    - 使用退避策略计算下一次超时时间。
    - 更新 `request_timeout`。
    - 增加 `retry_count`。
    - 将 `message` 和 `endpoint` 返回给调用者进行传输。
4. **如果耗尽**：
    - 将状态转换为 `Unrelated`。
    - 记录失败日志。

### 4. 传输接口
`check_timeouts` 将返回 `Result<Vec<(Url, Vec<u8>)>, Error>`。调用者（例如 `AsyncSecureStore` 循环或主应用程序）负责通过网络实际发送这些消息。

## 后果
- **可靠性**：暂时的网络故障不会中断握手。
- **流量**：重试会增加网络流量，但退避策略可以减轻风暴。
- **存储**：`VidContext` 的大小略有增加，以存储缓存的消息。
