use std::collections::VecDeque;
use std::time::Instant;
use url::Url;

/// A message that has been queued for later delivery.
///
/// This struct holds the raw encrypted message bytes and the destination URL,
/// along with a timestamp for potential expiration or ordering logic.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// The sealed TSP message payload.
    pub message: Vec<u8>,
    /// The destination URL for the message.
    pub url: Url,
    /// The time when this message was added to the queue.
    pub created_at: Instant,
}

/// An in-memory queue for storing messages that failed to send.
///
/// This queue uses a `VecDeque` to maintain FIFO (First-In-First-Out) order.
/// It is intended to hold messages temporarily when the transport is unavailable
/// or the recipient is offline.
///
/// # Example
///
/// ```
/// use tsp_sdk::queue::MessageQueue;
/// use url::Url;
///
/// let mut queue = MessageQueue::new();
/// let url = Url::parse("tcp://127.0.0.1:8080").unwrap();
/// queue.push(url, vec![1, 2, 3]);
///
/// assert!(!queue.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct MessageQueue {
    // Internal storage using a double-ended queue for efficient push/pop.
    queue: VecDeque<QueuedMessage>,
}

impl MessageQueue {
    /// Create a new, empty message queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a message onto the queue.
    pub fn push(&mut self, url: Url, message: Vec<u8>) {
        self.queue.push_back(QueuedMessage {
            message,
            url,
            created_at: Instant::now(),
        });
    }

    /// Pop the next message from the queue.
    pub fn pop(&mut self) -> Option<QueuedMessage> {
        self.queue.pop_front()
    }

    /// Peek at the next message in the queue.
    pub fn peek(&self) -> Option<&QueuedMessage> {
        self.queue.front()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get the number of messages in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_operations() {
        let mut queue = MessageQueue::new();
        let url = Url::parse("tcp://127.0.0.1:1337").unwrap();
        let msg1 = vec![1, 2, 3];
        let msg2 = vec![4, 5, 6];

        assert!(queue.is_empty());

        queue.push(url.clone(), msg1.clone());
        assert_eq!(queue.len(), 1);

        queue.push(url.clone(), msg2.clone());
        assert_eq!(queue.len(), 2);

        let popped1 = queue.pop().unwrap();
        assert_eq!(popped1.message, msg1);
        assert_eq!(popped1.url, url);

        let popped2 = queue.pop().unwrap();
        assert_eq!(popped2.message, msg2);

        assert!(queue.is_empty());
    }
}
