# TSP Test Vector Blockers

This document records currently known blockers that prevent parts of the test-vector set from being frozen as authoritative case-local assets.

It is part of the formal supporting document set for the test-vector effort.
It does not redefine vector semantics or relax any normative requirement from the specification.

## Purpose

This document exists to make the current freezing boundary explicit.

It records:

- which vectors are blocked
- why they are blocked
- whether the blocker comes from a known SDK divergence
- what class of follow-on work is required

## Current Confirmed Blockers

No currently confirmed blocker prevents the vector set from freezing the reviewed slices already defined in this document set.

## Confirmed SDK Divergences Relevant To Authoring

### Group E Negative Semantic Boundaries

The current SDK-path blocker is not a placeholder-authoring gap.
It is a reviewed implementation divergence observed during authoring probes for `CC-001 / HPKE-Auth`.

Observed behavior:

- the current SDK opens the `SV-004` probe as `ReceivedTspMessage::GenericMessage`
- the current SDK opens the `SV-006` probe as `ReceivedTspMessage::GenericMessage`

Current implementation-level explanation:

- `SV-004`
  - the encrypted `Payload::Content` path in `store.open_message` returns
    `ReceivedTspMessage::GenericMessage` after signature/decryption success,
    but does not enforce a prior-relationship authorization check
- `SV-006`
  - the encrypted `Payload::NestedMessage` path in `store.open_message`
    verifies that the inner sender is known, then recursively opens the inner
    message, but does not enforce the required coupled outer-context check

These divergences are now exposed both through replay-probe records and through
direct SDK consumer tests that show the canonical `SV-004` and `SV-006` wires
currently open as `ReceivedTspMessage::GenericMessage`.

This means the current SDK authoring path does not currently produce reviewed rejection baselines for:

- missing prior-relationship authorization
- missing coupled outer context

### Effect On Authoring

The abstract vector definitions remain valid.

This divergence no longer blocks the reviewed vector set itself because Group E is now frozen through a reviewed non-SDK derivation path across all three complete cases.

The divergence remains relevant for:

- future SDK correction work
- validator-facing consumption logic that may reuse SDK implementations
- later reviews of implementation conformance against the frozen Group E vectors

## Required Follow-On Work

One of the following is required before the SDK-path divergence can be removed:

1. author the negative vectors through a non-SDK path that can produce reviewed rejection baselines
2. change the SDK so that the required rejection semantics are actually enforced

The first path is now complete for the current vector-freezing effort.

## Working Rule

Known divergences must not be hidden by rewriting vectors to match current implementation behavior.

If a divergence still blocks freezing, it should be recorded explicitly as a blocker.
If freezing is completed through a reviewed alternative authoring path, the divergence should remain recorded, but no longer be described as an active vector-freezing blocker.
