# Versioning and Spec Diff Policy

This policy defines how the validation package tracks changes after the Rev 2 baseline.

## 1. Baseline Lock

- Baseline tag: `TSP-REV2`
- Baseline source: `https://trustoverip.github.io/tswg-tsp-specification/`
- Lock date: `2026-02-26`
- Current catalog version: `v1`

No clause renumbering is allowed within a locked baseline.

## 2. Clause Lifecycle States

- `Active`: required by current baseline
- `Superseded`: replaced by newer clause behavior in a later baseline
- `Deprecated`: retained for backward-reference only
- `Removed`: no longer applicable and excluded from active profiles

## 3. Change Types

Type A: Editorial-only change

- Wording clarification with no behavior change
- Action: keep Clause ID, update notes only

Type B: Behavioral change

- Requirement semantics changed
- Action: create new Clause ID and link predecessor as superseded

Type C: New requirement

- New normative clause appears
- Action: add new Clause ID and add mandatory matrix row

Type D: Requirement removal

- Clause removed from spec
- Action: mark old Clause ID deprecated or removed based on compatibility policy

## 4. Baseline Upgrade Procedure

1. Capture new spec snapshot and freeze source hash/reference.
2. Run clause diff against previous catalog.
3. Classify each change as Type A/B/C/D.
4. Update:
   - `01-spec-clause-catalog.md`
   - `02-conformance-matrix.md`
   - `05-known-gaps-vs-current-impl.md` (if impact changes)
5. Publish profile migration note:
   - from `TSP-REV2` to `TSP-REVX`
   - mandatory test delta list

## 5. Conformance Profiles and Claims

Profiles:

- `TSP-REV2-CORE`
- `TSP-REV2-EXTENDED`
- `TSP-REV2-FULL`

A conformance claim must specify:

- protocol baseline tag
- profile name
- implementation version/commit
- enabled feature set
- execution date and evidence bundle reference

## 6. Compatibility Rules

1. A profile claim for `TSP-REV2` cannot be reused for later baselines without rerun.
2. Feature-flag changes require re-validation for impacted clauses.
3. `SHOULD` and `MAY` capability claims must be explicit in implementation profile metadata.

## 7. Governance and Review

- Clause catalog changes require one protocol reviewer and one test-framework reviewer.
- Gap register changes require direct evidence references.
- Any unresolved ambiguity must be tagged `SPEC_GAP` and linked to an upstream issue discussion.

## 8. Artifacts Required Per Upgrade

- Updated clause catalog diff report
- Updated conformance matrix diff report
- Updated gap register
- New/retired test-vector manifest
