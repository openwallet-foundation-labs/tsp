# SDK Test-Vector Consumption Tests

This directory is reserved for SDK-side tests that consume the authoritative
test-vector package from `tsp_test_vectors`.

These tests should verify that `tsp_sdk` can consume frozen vector assets.
They should not become the long-term home of the authoritative assets,
appendix-facing documents, or authoring workflow itself.

These tests currently verify:

- the new package home under `tsp_test_vectors/`
- structural consumption of the frozen case packages through
  `tsp_test_vectors::validator::validate_all_packages(...)`
