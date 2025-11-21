use crate::definitions::{Digest, RelationshipStatus};

/// Events that trigger state transitions in the relationship lifecycle.
#[derive(Debug, Clone, PartialEq)]
pub enum RelationshipEvent {
    /// Sending a relationship request to a peer.
    SendRequest { thread_id: Digest },
    /// Receiving a relationship request from a peer.
    ReceiveRequest { thread_id: Digest },
    /// Sending an acceptance to a relationship request.
    SendAccept { thread_id: Digest },
    /// Receiving an acceptance to a relationship request.
    ReceiveAccept { thread_id: Digest },
    /// Sending a cancellation of the relationship.
    SendCancel,
    /// Receiving a cancellation of the relationship.
    ReceiveCancel,
    /// A request has timed out.
    Timeout,
}

/// Errors that can occur during state transitions.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StateError {
    #[error("Invalid state transition from {from:?} with event {event:?}")]
    InvalidTransition {
        from: RelationshipStatus,
        event: RelationshipEvent,
    },
    #[error("Thread ID mismatch: expected {expected:?}, got {got:?}")]
    ThreadIdMismatch { expected: Digest, got: Digest },
    #[error("Concurrency conflict: both parties requested relationship")]
    ConcurrencyConflict,
}

/// The Relationship State Machine governing lifecycle transitions.
pub struct RelationshipMachine;

impl RelationshipMachine {
    /// Transition the state based on the current state and the incoming event.
    pub fn transition(
        current: &RelationshipStatus,
        event: RelationshipEvent,
    ) -> Result<RelationshipStatus, StateError> {
        match (current, event) {
            // --- Unrelated Transitions ---
            (RelationshipStatus::Unrelated, RelationshipEvent::SendRequest { thread_id }) => {
                Ok(RelationshipStatus::Unidirectional { thread_id })
            }
            (RelationshipStatus::Unrelated, RelationshipEvent::ReceiveRequest { thread_id }) => {
                Ok(RelationshipStatus::ReverseUnidirectional { thread_id })
            }

            // --- Unidirectional Transitions (I requested) ---
            (
                RelationshipStatus::Unidirectional { thread_id: my_id },
                RelationshipEvent::ReceiveAccept { thread_id },
            ) => {
                if my_id == &thread_id {
                    Ok(RelationshipStatus::Bidirectional {
                        thread_id,
                        outstanding_nested_thread_ids: vec![],
                    })
                } else {
                    Err(StateError::ThreadIdMismatch {
                        expected: *my_id,
                        got: thread_id,
                    })
                }
            }
            (RelationshipStatus::Unidirectional { .. }, RelationshipEvent::SendCancel) => {
                Ok(RelationshipStatus::Unrelated)
            }
            (RelationshipStatus::Unidirectional { .. }, RelationshipEvent::Timeout) => {
                Ok(RelationshipStatus::Unrelated)
            }
            // Idempotency: Retrying the request
            (
                RelationshipStatus::Unidirectional {
                    thread_id: current_id,
                },
                RelationshipEvent::SendRequest { thread_id: new_id },
            ) => {
                if current_id == &new_id {
                    Ok(RelationshipStatus::Unidirectional {
                        thread_id: *current_id,
                    })
                } else {
                    // Starting a new request overrides the old one
                    Ok(RelationshipStatus::Unidirectional { thread_id: new_id })
                }
            }
            // Concurrency: I requested, but they also requested
            (
                RelationshipStatus::Unidirectional { .. },
                RelationshipEvent::ReceiveRequest { .. },
            ) => Err(StateError::ConcurrencyConflict),

            // --- ReverseUnidirectional Transitions (They requested) ---
            (
                RelationshipStatus::ReverseUnidirectional {
                    thread_id: their_id,
                },
                RelationshipEvent::SendAccept { thread_id },
            ) => {
                if their_id == &thread_id {
                    Ok(RelationshipStatus::Bidirectional {
                        thread_id,
                        outstanding_nested_thread_ids: vec![],
                    })
                } else {
                    Err(StateError::ThreadIdMismatch {
                        expected: *their_id,
                        got: thread_id,
                    })
                }
            }
            (RelationshipStatus::ReverseUnidirectional { .. }, RelationshipEvent::SendCancel) => {
                Ok(RelationshipStatus::Unrelated)
            }
            // Idempotency: Receiving the same request again
            (
                RelationshipStatus::ReverseUnidirectional {
                    thread_id: current_id,
                },
                RelationshipEvent::ReceiveRequest { thread_id: new_id },
            ) => {
                if current_id == &new_id {
                    Ok(RelationshipStatus::ReverseUnidirectional {
                        thread_id: *current_id,
                    })
                } else {
                    // They might have restarted the process
                    Ok(RelationshipStatus::ReverseUnidirectional { thread_id: new_id })
                }
            }

            // --- Bidirectional Transitions ---
            (RelationshipStatus::Bidirectional { .. }, RelationshipEvent::SendCancel)
            | (RelationshipStatus::Bidirectional { .. }, RelationshipEvent::ReceiveCancel) => {
                Ok(RelationshipStatus::Unrelated)
            }
            // Idempotency: Receiving request again when already connected
            (
                RelationshipStatus::Bidirectional {
                    thread_id: current_id,
                    ..
                },
                RelationshipEvent::ReceiveRequest { thread_id: new_id },
            ) => {
                if current_id == &new_id {
                    // Ignore duplicate request, stay connected
                    Ok(current.clone())
                } else {
                    // New request implies they might have lost state, but we treat it as a conflict or reset
                    // For now, let's assume it resets to ReverseUnidirectional to allow re-handshake
                    Ok(RelationshipStatus::ReverseUnidirectional { thread_id: new_id })
                }
            }
            // Idempotency: Receiving accept again
            (
                RelationshipStatus::Bidirectional {
                    thread_id: current_id,
                    ..
                },
                RelationshipEvent::ReceiveAccept { thread_id: new_id },
            ) => {
                if current_id == &new_id {
                    Ok(current.clone())
                } else {
                    Err(StateError::ThreadIdMismatch {
                        expected: *current_id,
                        got: new_id,
                    })
                }
            }

            // --- Invalid Transitions ---
            (state, event) => Err(StateError::InvalidTransition {
                from: state.clone(),
                event,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_digest(val: u8) -> Digest {
        [val; 32]
    }

    #[test]
    fn test_normal_flow_initiator() {
        let thread_id = mock_digest(1);
        let mut state = RelationshipStatus::Unrelated;

        // Send Request
        state =
            RelationshipMachine::transition(&state, RelationshipEvent::SendRequest { thread_id })
                .unwrap();
        assert!(matches!(state, RelationshipStatus::Unidirectional { .. }));

        // Receive Accept
        state =
            RelationshipMachine::transition(&state, RelationshipEvent::ReceiveAccept { thread_id })
                .unwrap();
        assert!(matches!(state, RelationshipStatus::Bidirectional { .. }));
    }

    #[test]
    fn test_normal_flow_receiver() {
        let thread_id = mock_digest(2);
        let mut state = RelationshipStatus::Unrelated;

        // Receive Request
        state = RelationshipMachine::transition(
            &state,
            RelationshipEvent::ReceiveRequest { thread_id },
        )
        .unwrap();
        assert!(matches!(
            state,
            RelationshipStatus::ReverseUnidirectional { .. }
        ));

        // Send Accept
        state =
            RelationshipMachine::transition(&state, RelationshipEvent::SendAccept { thread_id })
                .unwrap();
        assert!(matches!(state, RelationshipStatus::Bidirectional { .. }));
    }

    #[test]
    fn test_cancellation() {
        let thread_id = mock_digest(1);
        let state = RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: vec![],
        };

        let new_state =
            RelationshipMachine::transition(&state, RelationshipEvent::SendCancel).unwrap();
        assert!(matches!(new_state, RelationshipStatus::Unrelated));
    }

    #[test]
    fn test_thread_id_mismatch() {
        let thread_id_1 = mock_digest(1);
        let thread_id_2 = mock_digest(2);
        let state = RelationshipStatus::Unidirectional {
            thread_id: thread_id_1,
        };

        let err = RelationshipMachine::transition(
            &state,
            RelationshipEvent::ReceiveAccept {
                thread_id: thread_id_2,
            },
        )
        .unwrap_err();

        assert!(matches!(err, StateError::ThreadIdMismatch { .. }));
    }

    #[test]
    fn test_concurrency_conflict() {
        let thread_id = mock_digest(1);
        let state = RelationshipStatus::Unidirectional { thread_id };

        let err = RelationshipMachine::transition(
            &state,
            RelationshipEvent::ReceiveRequest {
                thread_id: mock_digest(2),
            },
        )
        .unwrap_err();

        assert_eq!(err, StateError::ConcurrencyConflict);
    }
}
