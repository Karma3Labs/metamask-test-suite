# Folders/Files Description

## `attack_vectors/*`
Contains the logic for test generation of each type of scenario and sub-cases that we want to test for.

### `attack_vectors/sybil/*`
The logic for sybil attestations are defined in the word document.

## `tests/*`
Unit tests for functions that generate `TrustCredential`s and `StatusCredential`s.

## `utils/*`
utility functions used in the generation of test-cases. 

# Instructions to run the script

## Run the script
In the top-level of the repository, run the following command:

### Creating folders for compute inputs
```
mkdir -p compute_inputs/simple_sybil
mkdir -p compute_inputs/sleeper_sybil/all_pretrust
mkdir -p compute_inputs/sleeper_sybil/one_pretrust
mkdir -p compute_inputs/full_mesh_sybil
```

### Creating folders for compute outputs (compute results)
```
mkdir -p compute_outputs/simple_sybil
mkdir -p compute_outputs/sleeper_sybil/all_pretrust
mkdir -p compute_outputs/sleeper_sybil/one_pretrust
mkdir -p compute_outputs/full_mesh_sybil
```

### modify `main.py` as desired and run it using the command:
```
python3 main.py <sybil_cluster_size>
```
