# Folders/Files Description

## `attack_vectors/*`
Contains the logic for test generation of each type of scenario and sub-cases that we want to test for.

### `attack_vectors/bored_influencer/*`
TODO

### `attack_vectors/classic_sybil/*`
The logic for sybil attestations are defined here. There are 2 sub-cases:

#### sybils_with_auditor_trust
1. Sybil origin (which has received a `TrustCredential` from a `Trust Anchor`) propagates that trust to sybil wallets.
2. Sybil wallets either:
    - Endorse a malicious snap
    - Dispute an honest snap

#### sybils_without_auditor_trust
Similar to the testcase above, except we omitted step (1) to simulate sybil wallets without any `TrustCredential`s.

### `attack_vectors/trickle_sybil/*`
TODO

## `network_inputs/*`
- Contains 3 sub-folders, each representing a type of node in the social graph.
- Files with the `initial_*` prefix are used for generation of the initial network state.
- To change the number of network participants, add/remove from the respective `.json` files.

### `network_inputs/network_participants/*`
The number of `EOA`s that are participating in the network are defined here.
1. `non_auditors` will NOT receive any `TrustCredential`s from `Trust Anchor`s.
2. `trusted_auditors` will receive a (`Software Security`, `1`) `TrustCredential` from `Trust Anchor`s.
2. `untrusted_auditors` will receive a (`Software Security`, `-1`) `TrustCredential` from `Trust Anchor`s.

### `network_inputs/trust_anchors/*`
The number of `Trust Anchor`s that are participating in the network are defined here.

### `network_inputs/snaps/*`
The number of `Snap`s that are participating in the network are defined here. There are 2 types: `honest` and `malicious` snaps.

## `tests/*`
Unit tests for functions that generate `TrustCredential`s and `StatusCredential`s.

## `utils/*`
utility functions used in the generation of test-cases. 

## `main.py`
Running this via the command `python3 main.py` in the root-level of the repo will generate 2 files:
1. `initial_network_state.json`
2. `sybils_with_auditor_trust.json` and/or `sybils_without_auditor_trust.json` (depending on which block on code is commented out)

Appending (2) after (1) will give a list of attestation that simulates the specified type of sybil attack that happens after network initialisation