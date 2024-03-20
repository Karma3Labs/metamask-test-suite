from utils.common import generate_input_csv_file

from utils.init_network import run_init_network_state
from attack_vectors.sybil.simple_sybil import run_execute_simple_sybil_endorse
from attack_vectors.sybil.sybil_with_sleeper import run_execute_sleeper_sybil_endorse_all_pretrust
from attack_vectors.sybil.sybil_with_sleeper import run_execute_sleeper_sybil_endorse_one_pretrust
from attack_vectors.sybil.full_mesh_sybil import run_execute_full_mesh_sybil_endorse


if __name__ == "__main__":

    generate_input_csv_file(
        init_network_attestations_list=run_init_network_state(),
        scenario_attestations_list=run_execute_simple_sybil_endorse(),
        file_name="simple_sybil_input.csv"
    )

    #generate_input_csv_file(
    #    init_network_attestations_list=init_network_state(),
    #    scenario_attestations_list=run_execute_full_mesh_sybil_endorse(),
    #    file_name="full_mesh_sybil_input.csv"
    #)

    #generate_input_csv_file(
    #    init_network_attestations_list=init_network_state(),
    #    scenario_attestations_list=run_execute_sleeper_sybil_endorse_one_pretrust(),
    #    file_name="sleeper_sybil_endorse_one_pretrust_input.csv"
    #)

    #generate_input_csv_file(
    #    init_network_attestations_list=init_network_state(),
    #    scenario_attestations_list=run_execute_sleeper_sybil_endorse_all_pretrust(),
    #    file_name="sleeper_sybil_endorse_all_pretrust_input.csv"
    #)

# ./run_simulation.sh /Users/cheeweetan/Desktop/metamask/rs-eigentrust/simple_sybil_input.csv /Users/cheeweetan/Desktop/metamask/rs-eigentrust/pretrust.txt