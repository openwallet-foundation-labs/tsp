# TSP New Features (State Machine, Retry, Queue) in Perfect Scenarios

This document demonstrates how our three newly implemented features: **Relationship State Machine**, **Retry Mechanism**, and **Offline Message Queue**, play a critical role in the six perfect scenarios of TSP.

## 1. AI Agent Secure Communication (TMCP)

*   **Relationship State Machine**:
    *   **Scenario**: Two AI Agents (e.g., "Booking Agent" and "Payment Agent") establish a trust connection for the first time.
    *   **Application**: The state machine ensures the atomicity and consistency of the handshake process. If both Agents initiate connection requests to each other simultaneously (concurrency conflict), the state machine automatically decides which request to keep by comparing `thread_id`, avoiding deadlock or state inconsistency, ensuring smooth connection establishment.
*   **Retry Mechanism**:
    *   **Scenario**: Agents running in a Serverless environment may have cold start latency.
    *   **Application**: When the "Booking Agent" sends a request, if the "Payment Agent" is cold starting and not responding, the retry mechanism automatically performs exponential backoff retries (500ms -> 750ms -> ...), until the other party starts and responds, without manual intervention.
*   **Offline Message Queue**:
    *   **Scenario**: Agents may hibernate to save costs after completing tasks.
    *   **Application**: If the "Payment Agent" is hibernating, confirmation messages sent by the "Booking Agent" enter the offline queue. Once the "Payment Agent" wakes up and comes online, messages are automatically delivered, ensuring no transaction records are lost.

## 2. Enterprise B2B Encrypted Communication

*   **Relationship State Machine**:
    *   **Scenario**: In a supply chain system, suppliers and manufacturers establish long-term cooperative relationships.
    *   **Application**: The state machine manages the lifecycle of the relationship. When the cooperation ends, one party sends a `SendCancel` event, and the state machine ensures both parties' states synchronously transition to `Unrelated`, preventing old keys from being misused.
*   **Retry Mechanism**:
    *   **Scenario**: Cross-border enterprise communication across the public internet with frequent network jitter.
    *   **Application**: When sending critical purchase orders, if timeouts occur due to packet loss, the retry mechanism ensures the order is eventually delivered, avoiding missing orders due to network fluctuations.
*   **Offline Message Queue**:
    *   **Scenario**: Enterprise ERP systems undergoing routine weekend maintenance.
    *   **Application**: Shipping notifications sent by partners during maintenance will not fail with an error but are temporarily stored in the queue. After the system comes back online on Monday, the backlog of notifications is automatically processed, seamlessly connecting business processes.

## 3. Whistleblower Protection System

*   **Relationship State Machine**:
    *   **Scenario**: A whistleblower establishes a one-time anonymous contact with a journalist.
    *   **Application**: The state machine strictly defines the handshake process, preventing man-in-the-middle attacks from confusing the situation or probing states by replaying old handshake packets. Any illegal transition request not matching the current state will be rejected.
*   **Retry Mechanism**:
    *   **Scenario**: Whistleblowers using the Tor network or unstable public Wi-Fi.
    *   **Application**: In high-latency or unstable network environments, the retry mechanism greatly increases the probability of successful message transmission, reducing the risk of the whistleblower exposing their location due to multiple attempts after failure.
*   **Offline Message Queue**:
    *   **Scenario**: Journalists only coming online to receive messages during specific time windows for safety.
    *   **Application**: Whistleblowers can send leak materials at any time, which are stored in the queue. Journalists pull them all at once when online, achieving asynchronous secure communication and protecting both parties' time pattern privacy.

## 4. Scenarios Requiring Metadata Privacy (e.g., Medical Consultation)

*   **Relationship State Machine**:
    *   **Scenario**: Establishing multi-hop routing connections.
    *   **Application**: When establishing each hop of nested relationships, the state machine ensures each layer of the link (Patient -> Relay A, Relay A -> Relay B) is correctly established. If any intermediate hop fails, the state machine can quickly rollback via timeout mechanisms, avoiding "headless" links.
*   **Retry Mechanism**:
    *   **Scenario**: Multi-hop routing increases link instability.
    *   **Application**: If a relay node in the link is temporarily congested, the retry mechanism gives it some buffer time instead of immediately disconnecting the entire anonymous link, improving the stability of long-link communication.
*   **Offline Message Queue**:
    *   **Scenario**: Relay node rotation.
    *   **Application**: If the next-hop relay node is changing keys or rebooting, messages can be temporarily stored at the current node and forwarded after the next hop recovers, enhancing the anti-interference ability of the anonymous network.

## 5. Scenarios Requiring Verifiable Identity (e.g., Supply Chain Finance)

*   **Relationship State Machine**:
    *   **Scenario**: Banks verifying the identity of logistics companies.
    *   **Application**: The state machine ensures identity verification (handshake) is a prerequisite. Only after the state becomes `Bidirectional` will the bank process shipping data sent by the other party, fundamentally preventing data injection attacks from unverified identities.
*   **Retry Mechanism**:
    *   **Scenario**: IoT devices (e.g., container trackers) with unstable signals.
    *   **Application**: When a tracker reports location data, if sending fails due to poor signal, the retry mechanism ensures data is resent after the signal recovers, guaranteeing the bank sees a complete logistics trajectory.
*   **Offline Message Queue**:
    *   **Scenario**: Bank systems settling accounts at night, pausing external services.
    *   **Application**: Logistics data enters the queue during settlement and is automatically booked after settlement ends, ensuring the integrity and timeliness of financial data.

## 6. Scenarios Requiring Integration into Existing Systems (e.g., Legacy Bank SWIFT Upgrade)

*   **Relationship State Machine**:
    *   **Scenario**: Coexistence of new and old systems.
    *   **Application**: The state machine provides clear `Unrelated` / `Bidirectional` state indicators, facilitating integration code to judge when to send encrypted messages via TSP and when to fallback to the legacy system or initiate a handshake.
*   **Retry Mechanism**:
    *   **Scenario**: Slow processing speed of legacy systems causing timeouts at the TSP layer.
    *   **Application**: The retry mechanism naturally adapts to the processing rhythm of legacy systems through exponential backoff, avoiding frequent errors due to legacy system business, playing a "peak clipping and valley filling" role.
*   **Offline Message Queue**:
    *   **Scenario**: System decoupling.
    *   **Application**: The TSP gateway acts as an "Outbox". The core banking system only needs to "throw" the message into the TSP SDK queue to return, without synchronously waiting for network sending results. This significantly reduces integration coupling and improves the throughput of the core system.
