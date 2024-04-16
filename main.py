import sys

from utils.common import generate_input_csv_file

from utils.init_network import run_init_network_state
from attack_vectors.sybil.simple_sybil import run_execute_simple_sybil_endorse
from attack_vectors.sybil.sybil_with_sleeper import run_execute_sleeper_sybil_endorse_all_pretrust
from attack_vectors.sybil.sybil_with_sleeper import run_execute_sleeper_sybil_endorse_one_pretrust
from attack_vectors.sybil.full_mesh_sybil import run_execute_full_mesh_sybil_endorse


# Usage: python3 main.py <sybil_cluster_size>
# e.g. python3 main.py 10
if __name__ == "__main__":

    sybil_cluster_size = int(sys.argv[1])

    file_name, scenario_attestations_list = run_execute_simple_sybil_endorse(sybil_cluster_size=sybil_cluster_size)
    #file_name, scenario_attestations_list = run_execute_full_mesh_sybil_endorse(sybil_cluster_size=sybil_cluster_size)
    #file_name, scenario_attestations_list = run_execute_sleeper_sybil_endorse_one_pretrust(sybil_cluster_size=sybil_cluster_size)
    #file_name, scenario_attestations_list = run_execute_sleeper_sybil_endorse_all_pretrust(sybil_cluster_size=sybil_cluster_size)

    generate_input_csv_file(
        init_network_attestations_list=run_init_network_state(),
        scenario_attestations_list=scenario_attestations_list,
        file_name=file_name
    )

# ./run_simulation.sh /Users/cheeweetan/Desktop/metamask/rs-eigentrust/simple_sybil_input.csv /Users/cheeweetan/Desktop/metamask/rs-eigentrust/pretrust.txt
#./run_simulation.sh /Users/cheeweetan/Desktop/metamask-test-suite/compute_inputs/simple_sybil/simple_sybil_1_sybil_peers.csv /Users/cheeweetan/Desktop/rs-eigentrust/pretrust.txt
