import sys
sys.path.append('../..')

from utils.init_network import init_network_state
from utils.common import generate_endorse_snap_payload, generate_trust_credential_with_swe_and_auditor_role


"""
1. pretrusted peers endorses sybil peer
2. sybil peer starts chain of endorsement among sybil wallets
3. sybil cluster endorses malicious snaps
"""
def create_sybil_cluster(pretrusted_peers: list, pretrusted_endorsement_num: int, sybil_root_peer_id: str, sybil_cluster_size: int):
    attestation_payload_list = []

    # 1. pretrusted peers endorses sybil peer
    for peer in pretrusted_peers[0:pretrusted_endorsement_num]:
        attestation_payload = generate_trust_credential_with_swe_and_auditor_role(
            src_address=peer,
            dest_address=sybil_root_peer_id,
            swe_trust_level=1,
            auditor_trust_level=1    
        )
        attestation_payload_list.append(attestation_payload)

    sybil_cluster_peer_id_list = [sybil_root_peer_id]
    for i in range(0,sybil_cluster_size):
        sybil_cluster_peer_id = f"sybil_cluster_peer_{i+1}"
        sybil_cluster_peer_id_list.append(sybil_cluster_peer_id)

    # 2. sybil peer initialises chain of endorsement
    endorse_sybil_cluster_attestation_payload_list = []
    for i in range(len(sybil_cluster_peer_id_list) - 1):
        _from = sybil_cluster_peer_id_list[i]
        _to = sybil_cluster_peer_id_list[i + 1]
        endorse_sybil_cluster_attestation_payload = generate_trust_credential_with_swe_and_auditor_role(
            src_address=_from,
            dest_address=_to,
            swe_trust_level=1,
            auditor_trust_level=1    
        )
        endorse_sybil_cluster_attestation_payload_list.append(endorse_sybil_cluster_attestation_payload)

    return attestation_payload_list + endorse_sybil_cluster_attestation_payload_list, sybil_cluster_peer_id_list


def execute_sybil_endorse(pretrusted_peers: list, pretrusted_endorsement_num: int, sybil_root_peer_id: str, sybil_cluster_size: int, bad_snap_id: str):
    create_sybil_cluster_attestation_list, sybil_cluster_peer_id_list = create_sybil_cluster(
        pretrusted_peers=pretrusted_peers,
        pretrusted_endorsement_num = pretrusted_endorsement_num,
        sybil_root_peer_id=sybil_root_peer_id,
        sybil_cluster_size=sybil_cluster_size
    )

    # 3: sybil cluster endorses malicious snaps
    endorse_malicious_snaps_attestation_list = []

    for sybil_peer_id in sybil_cluster_peer_id_list:
        endorse_malicious_snaps_attestation = generate_endorse_snap_payload(
            src_address=sybil_peer_id,
            snap_checksum=bad_snap_id,
            reasons={}
        )
        endorse_malicious_snaps_attestation_list.append(endorse_malicious_snaps_attestation)
    
    return create_sybil_cluster_attestation_list + endorse_malicious_snaps_attestation_list


def execute_sybil_endorse_one_pretrust(pretrusted_peers: list, sybil_root_peer_id: str, sybil_cluster_size: int, bad_snap_id: str):
    execute_sybil_endorse_attestations = execute_sybil_endorse(
        pretrusted_peers=pretrusted_peers,
        pretrusted_endorsement_num = 1,
        sybil_root_peer_id=sybil_root_peer_id,
        sybil_cluster_size=sybil_cluster_size,
        bad_snap_id=bad_snap_id
    )

    return execute_sybil_endorse_attestations


def execute_sybil_endorse_all_pretrust(pretrusted_peers: list, sybil_root_peer_id: str, sybil_cluster_size: int, bad_snap_id: str):
    execute_sybil_endorse_attestations = execute_sybil_endorse(
        pretrusted_peers=pretrusted_peers,
        pretrusted_endorsement_num = len(pretrusted_peers),
        sybil_root_peer_id=sybil_root_peer_id,
        sybil_cluster_size=sybil_cluster_size,
        bad_snap_id=bad_snap_id
    )

    return execute_sybil_endorse_attestations


def run_execute_sleeper_sybil_endorse_all_pretrust(sybil_cluster_size):
    mock_pretrusted_peers = [
        'pretrusted_peer_id_1',
        'pretrusted_peer_id_2',
        'pretrusted_peer_id_3',
    ]
    mock_normal_peers = [
        'normal_peer_id_1',
        'normal_peer_id_2',
        'normal_peer_id_3',
        'normal_peer_id_4',
        'normal_peer_id_5',
    ]
    mock_snaps = [
        'snap_id_1',
        'snap_id_2',
        'snap_id_3',
    ]

    mock_bad_snap_id = 'bad_snap_id_1'
    mock_rouge_peer_id = 'normal_peer_id_1' # sleeper agent
    mock_sybil_cluster_size = sybil_cluster_size # modifiy this to change the size of sybil cluster

    initialise_network_attestations = init_network_state(
        pretrusted_peers=mock_pretrusted_peers,
        normal_peers=mock_normal_peers,
        snaps=mock_snaps
    )

    execute_sybil_endorse_attestations = execute_sybil_endorse_all_pretrust(
        pretrusted_peers=mock_pretrusted_peers,
        sybil_root_peer_id=mock_rouge_peer_id,
        sybil_cluster_size=mock_sybil_cluster_size,
        bad_snap_id=mock_bad_snap_id
    )

    return f"compute_inputs/sleeper_sybil/all_pretrust/sleeper_sybil_all_pretrust_{sybil_cluster_size}_sybil_peers.csv", initialise_network_attestations + execute_sybil_endorse_attestations


def run_execute_sleeper_sybil_endorse_one_pretrust(sybil_cluster_size):
    mock_pretrusted_peers = [
        'pretrusted_peer_id_1',
        'pretrusted_peer_id_2',
        'pretrusted_peer_id_3',
    ]
    mock_normal_peers = [
        'normal_peer_id_1',
        'normal_peer_id_2',
        'normal_peer_id_3',
        'normal_peer_id_4',
        'normal_peer_id_5',
    ]
    mock_snaps = [
        'snap_id_1',
        'snap_id_2',
        'snap_id_3',
    ]

    mock_bad_snap_id = 'bad_snap_id_1'
    mock_rouge_peer_id = 'normal_peer_id_1' # sleeper agent
    mock_sybil_cluster_size = sybil_cluster_size # modifiy this to change the size of sybil cluster

    initialise_network_attestations = init_network_state(
        pretrusted_peers=mock_pretrusted_peers,
        normal_peers=mock_normal_peers,
        snaps=mock_snaps
    )

    execute_sybil_endorse_attestations = execute_sybil_endorse_one_pretrust(
        pretrusted_peers=mock_pretrusted_peers,
        sybil_root_peer_id=mock_rouge_peer_id,
        sybil_cluster_size=mock_sybil_cluster_size,
        bad_snap_id=mock_bad_snap_id
    )

    return f"compute_inputs/sleeper_sybil/one_pretrust/sleeper_sybil_one_pretrust_{sybil_cluster_size}_sybil_peers.csv", initialise_network_attestations + execute_sybil_endorse_attestations


if __name__ == "__main__":
    pass
