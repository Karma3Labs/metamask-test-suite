import sys
sys.path.append('..')

from utils.common import generate_endorse_snap_payload, generate_trust_credential_with_swe_and_auditor_role

def init_network_state(pretrusted_peers: list, normal_peers: list, snaps: list):
    attestation_payload_list = []

    # all pretrusted peers issue trust to all normal_peers
    for peer in normal_peers:
        for pt_peer in pretrusted_peers:
            attestation_payload = generate_trust_credential_with_swe_and_auditor_role(
                src_address=pt_peer,
                dest_address=peer,
                swe_trust_level=1,
                auditor_trust_level=1    
            )
            attestation_payload_list.append(attestation_payload)

    # all normal_peers issue endorsements to snaps
    for peer in normal_peers:
        for snap in snaps:
            endorse_snaps_attestation = generate_endorse_snap_payload(
                src_address=peer,
                snap_checksum=snap,
                reasons={}
            )
            attestation_payload_list.append(endorse_snaps_attestation)

    return attestation_payload_list


def run_init_network_state():
    init_network_attestations_list = init_network_state(
        pretrusted_peers=[
            'pretrusted_peer_id_1',
            'pretrusted_peer_id_2',
            'pretrusted_peer_id_3',
        ],
        normal_peers=[
            'normal_peer_id_1',
            'normal_peer_id_2',
            'normal_peer_id_3',
            'normal_peer_id_4',
            'normal_peer_id_5',
        ],
        snaps=[
            'snap_id_1',
            'snap_id_2',
            'snap_id_3',
        ]
    )

    return init_network_attestations_list


if __name__ == "__main__":
    x = init_network_state(
        pretrusted_peers=[
            'pretrusted_peer_id_1',
            'pretrusted_peer_id_2',
            'pretrusted_peer_id_3',
        ],
        normal_peers=[
            'normal_peer_id_1',
            'normal_peer_id_2',
            'normal_peer_id_3',
            'normal_peer_id_4',
            'normal_peer_id_5',
        ],
        snaps=[
            'snap_id_1',
            'snap_id_2',
            'snap_id_3',
        ]
    )
    for y in x:
        print(y)
        print('\n')
