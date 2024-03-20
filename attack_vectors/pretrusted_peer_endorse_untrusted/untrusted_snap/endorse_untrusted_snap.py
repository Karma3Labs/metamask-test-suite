import sys
sys.path.append('../../..')

from utils.common import generate_endorse_snap_payload


"""
Test Case 1: Pre-trusted peer endorse untrustworthy Snaps

Test case description:
  - pre-trusted peers are endorsing a vulnerable or scammy snap

Expected result: 
  - Snap community sentiment is not “endorsed”
"""
def execute(bad_snap_id: str, pretrusted_peers: list):
    attestation_list = []

    for peer in pretrusted_peers:
        attestation = generate_endorse_snap_payload(
            src_address=peer,
            snap_checksum=mock_bad_snap_id,
            reasons={}
        )
        attestation_list.append(attestation)

    return attestation_list


if __name__ == "__main__":
    mock_pretrusted_peers = [
        'pretrusted_peer_id_1',
        'pretrusted_peer_id_2',
        'pretrusted_peer_id_3',
    ]
    mock_bad_snap_id = 'bad_snap_id_1'

    attestation_list = execute(
        bad_snap_id=mock_bad_snap_id,
        pretrusted_peers=mock_pretrusted_peers
    )

    for attestation in attestation_list:
        print(attestation_list)
