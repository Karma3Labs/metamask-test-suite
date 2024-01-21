# Folders/Files Description

## `attack_vectors/*`
Contains the logic for test generation of each type of scenario and sub-cases that we want to test for.

### `attack_vectors/bored_influencer/*`
TODO

### `attack_vectors/classic_sybil/*`
TODO

### `attack_vectors/trickle_sybil/*`
TODO

## `network_inputs/*`
Contains 3 sub-folders, each representing a type of node in the social graph

### `network_inputs/network_participants/*`
TODO

### `network_inputs/trust_anchors/*`
TODO

### `network_inputs/snaps/*`
TODO

## `tests/*`
Unit tests for functions that generate `TrustCredential`s and `StatusCredential`s.

## `utils/*`
utility functions used in the generation of test-cases. 

## `main.py`
Running this in the root-level of the repo will generate 2 files:
1. `initial_network_state.json`
2. `sybils_with_auditor_trust.json` and/or `sybils_without_auditor_trust.json` (depending on which block on code is commented out)

Appending (2) after (1) will give a list of attestation that simulates the specified type of sybil attack that happens after network initialisation