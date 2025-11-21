# 三個新功能中新增的所有測試用例

以下是這三個新功能中新增的所有測試用例：

### 1. 關係狀態機 (Relationship State Machine)
文件：`tsp_sdk/src/relationship_machine.rs`

*   **`test_normal_flow_initiator`**: 測試發起方從 `Unrelated` -> `Unidirectional` (SendRequest) -> `Bidirectional` (ReceiveAccept) 的正常流程。
*   **`test_normal_flow_receiver`**: 測試接收方從 `Unrelated` -> `ReverseUnidirectional` (ReceiveRequest) -> `Bidirectional` (SendAccept) 的正常流程。
*   **`test_cancellation`**: 測試從 `Bidirectional` 狀態發送取消 (`SendCancel`) 後回到 `Unrelated` 狀態。
*   **`test_thread_id_mismatch`**: 測試在 `Unidirectional` 狀態下收到 `thread_id` 不匹配的 `ReceiveAccept` 事件時，是否正確返回 `ThreadIdMismatch` 錯誤。
*   **`test_concurrency_conflict`**: 測試在 `Unidirectional` 狀態下收到 `ReceiveRequest` (對方也發起請求) 時，是否正確返回 `ConcurrencyConflict` 錯誤。

### 2. 重試機制 (Retry Mechanism)
文件：`tsp_sdk/src/retry.rs`

*   **`test_backoff`**: 測試指數退避策略的計算是否正確（例如：1s -> 2s -> 4s），以及達到最大重試次數後是否返回 `None`。
*   **`test_max_delay`**: 測試計算出的延遲時間是否被 `max_delay` 正確限制（例如：計算出 10s 但上限是 5s，應返回 5s）。

### 3. 離線消息隊列 (Offline Message Queue)
文件：`tsp_sdk/src/queue.rs`

*   **`test_queue_operations`**: 測試隊列的基本操作，包括：
    *   `is_empty()`: 檢查空隊列。
    *   `push()`: 添加消息，檢查 `len()`。
    *   `pop()`: 取出消息，驗證 FIFO 順序（先進先出）和內容正確性。
