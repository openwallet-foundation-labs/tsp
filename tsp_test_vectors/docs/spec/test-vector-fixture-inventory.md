# TSP Test Vector Fixture Inventory

This document inventories the supporting fixtures referenced by the TSP test-vector set.

Fixtures provide stable shared references for vectors. They do not replace vectors, and they do not standardize wallet layout, local storage, or identity lifecycle policy.
Each complete case declares its own applicability using these shared fixture IDs. `CC-001`, `CC-002`, and `CC-003` realize the full shared fixture inventory.

This inventory contains:

- `10` identity fixtures
- `14` conversation fixtures

The corresponding `fixture-only` definitions are recorded in [test-vector-fixtures.md](./test-vector-fixtures.md).

## Fixture Principles

- fixture IDs are stable references reused by vectors
- fixture scope is explicit; fixtures from different scopes are distinct in the set
- fixture material supports vector assertions but is not protocol truth by itself
- each complete case declares its own fixture applicability using these shared IDs
- shared fixture IDs do not imply one shared artifact file across all confidentiality mechanisms

## Identity Fixtures

| Fixture ID | Scope | Role | Used by |
| --- | --- | --- | --- |
| `fixture.identity.direct.alice` | direct | direct sender or receiver identity | `BV-001`, `BV-002`, `BV-003`, `SV-001`, `SV-004`, `SV-005` |
| `fixture.identity.direct.bob` | direct | direct sender or receiver identity | `BV-001`, `BV-002`, `BV-003`, `SV-001`, `SV-004`, `SV-005` |
| `fixture.identity.outer.alice` | nested outer | outer nested relationship participant | `BV-004`, `BV-005`, `SV-002`, `SV-006` |
| `fixture.identity.outer.bob` | nested outer | outer nested relationship participant | `BV-004`, `BV-005`, `SV-002`, `SV-006` |
| `fixture.identity.inner.alice-1` | nested inner | inner nested relationship participant | `BV-004`, `BV-005`, `SV-002`, `SV-006` |
| `fixture.identity.inner.bob-1` | nested inner | inner nested relationship participant | `BV-005`, `SV-002`, `SV-006` |
| `fixture.identity.route.alice` | routed endpoint | routed-path endpoint or logical sender | `BV-006`, `BV-007`, `BV-008`, `SV-003` |
| `fixture.identity.route.bob` | routed endpoint | routed-path endpoint or final receiver | `BV-006`, `BV-007`, `BV-008`, `SV-003` |
| `fixture.identity.route.hop-1` | routed intermediary | first intermediary hop | `BV-006`, `BV-007`, `BV-008`, `SV-003` |
| `fixture.identity.route.hop-2` | routed intermediary | second intermediary hop or next hop | `BV-006`, `BV-007`, `BV-008`, `SV-003` |

## Conversation Fixtures

| Fixture ID | Scope | Role | Used by |
| --- | --- | --- | --- |
| `fixture.conversation.direct.request-01` | direct | reviewed request binding material | `BV-001`, `BV-002`, `SV-005` |
| `fixture.conversation.direct.accept-01` | direct | reviewed positive accept binding material | `BV-002` |
| `fixture.conversation.direct.rfd-01` | direct | reviewed decline-or-cancel binding material | `BV-003` |
| `fixture.conversation.direct.message-01` | direct | reviewed direct confidential generic-message context | `SV-001` |
| `fixture.conversation.negative.no-prior-relationship-01` | negative | unauthorized direct generic-message case | `SV-004` |
| `fixture.conversation.negative.digest-mismatch-01` | negative | direct accept with non-matching digest | `SV-005` |
| `fixture.conversation.negative.nested-without-outer-01` | negative | nested traffic reviewed without the required coupled outer context | `SV-006` |
| `fixture.conversation.nested.request-01` | nested | reviewed nested request binding material | `BV-004`, `BV-005` |
| `fixture.conversation.nested.accept-01` | nested | reviewed positive nested accept binding material | `BV-005` |
| `fixture.conversation.nested.message-01` | nested | reviewed nested confidential-message context | `SV-002` |
| `fixture.conversation.routed.path-01` | routed | reviewed routed hop path context | `BV-006`, `SV-003` |
| `fixture.conversation.routed.request-01` | routed | reviewed routed request binding material | `BV-007` |
| `fixture.conversation.routed.accept-01` | routed | reviewed routed accept binding material | `BV-008` |
| `fixture.conversation.routed.message-01` | routed | reviewed routed confidential-message context | `SV-003` |

## Minimum Field Boundary

- an identity fixture freezes:
  - `id`
  - `scope`
  - `identifier`
  - `public_material`
  - `transport_or_route_role`, if applicable
- a conversation fixture freezes:
  - `id`
  - `scope`
  - `related_identity_fixtures`
  - `binding_material`
  - `used_by_vectors`
