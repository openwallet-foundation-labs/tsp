# Real-World Application Examples of New Features

These three new features (Relationship State Machine, Retry Mechanism, Offline Message Queue) together form the foundation of a robust communication system capable of adapting to unstable network environments. The following is a real-world application example showing how they work together:

### Application Scenario: Smart Home Control System

Suppose you have a **Smartphone App (Controller)** and a **Smart Lock (Device)**. They communicate securely via the TSP protocol.

#### 1. Relationship Establishment (Relationship State Machine)
**Scenario**: You just bought a smart lock and are pairing it with the mobile App for the first time.

*   **Real-world Process**:
    1.  You click "Add Device" on the App, and the App sends a `RequestRelationship` message to the lock.
    2.  **Role of State Machine**: The App's state changes to `Unidirectional` (requesting), and the lock's state changes to `ReverseUnidirectional` upon receipt.
    3.  The lock verifies your identity (e.g., pressing a physical button) and then sends `AcceptRelationship`.
    4.  **Role of State Machine**: The App receives the acceptance message, and the state changes to `Bidirectional` (connected). Both parties can now communicate securely.
*   **Problem Solved**: If your spouse is also using their mobile App to pair with the same lock at the same time, the **Concurrency Handling** logic of the state machine ensures that only one request succeeds, or resolves conflicts systematically based on `thread_id` rules, avoiding chaotic lock states.

#### 2. Automatic Retry (Retry Mechanism)
**Scenario**: You come home and walk to the door, clicking the "Unlock" button on the App. However, your home Wi-Fi signal just fluctuated, or the 4G signal is very poor.

*   **Real-world Process**:
    1.  The App sends an "Unlock" command (this is a TSP message).
    2.  Due to network fluctuations, the message is not sent out, or the lock does not receive it.
    3.  **Role of Retry Mechanism**: The App does not immediately report an error saying "Unlock failed". It waits for 500ms and then automatically retries. If it still doesn't work, it waits for 750ms and tries again.
    4.  On the second retry, the network recovers, and the message is successfully sent. The door opens.
*   **User Experience**: You don't feel that there was a network problem; you just feel that the door opened after clicking the button (maybe 0.5 seconds slower), instead of seeing an annoying "Connection timeout, please retry" popup.

#### 3. Offline Message Queue (Offline Message Queue)
**Scenario**: You have left for work and want to remotely authorize a temporary password for a courier. However, your home Wi-Fi router suddenly lost power, and the smart lock is offline.

*   **Real-world Process**:
    1.  You send a command "Set temporary password: 1234" using the App at the office.
    2.  The App attempts to connect to the lock and finds it unreachable (Transport Error).
    3.  **Role of Message Queue**: The App does not discard this command but places it into the **Offline Message Queue**.
    4.  The App checks periodically in the background, or when you return home and your phone connects to the home Wi-Fi, or when the lock comes back online and sends a heartbeat packet, the App detects connection recovery.
    5.  **Queue Flushing**: The App automatically retrieves the "Set temporary password" command from the queue and sends it out.
*   **Problem Solved**: Ensures that critical instructions (such as authorization, revocation of permissions) are not lost due to the device being temporarily offline. You don't need to keep staring at the App waiting for the device to come online to manually send it again.

#### 4. **Integration Tests**

```bash
cargo run -p examples --bin smart-home-lock
```

### Summary
*   **State Machine** ensures the logical correctness and security of the **"Connection"** process.
*   **Retry Mechanism** resolves **"Transient"** network issues.
*   **Message Queue** resolves **"Long-term"** offline issues.

The combination of these three enables the TSP SDK to support real-world applications with high reliability requirements, such as Smart Home, Internet of Things (IoT), and Instant Messaging (IM).
