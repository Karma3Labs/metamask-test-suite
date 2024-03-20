import sys
sys.path.append('../../..')

from utils.common import generate_trust_credential_with_swe_and_auditor_role, generate_endorse_snap_payload, generate_endorse_


"""
Test Case 2: Trusted peer endorse untrustworthy Snap

Test case description: 
  - 1. A pre-trusted peer is endorsing a trusted peer
  - 2. trusted peer then endorse a malicious peer
Expected result: 
"""
def execute(trusted_peer_id: str, bad_peer_id: str, pretrusted_peers: list):
    attestation_payload_list = []

    # 1. Each pre-trusted peer endorses the malicious peer
    for peer in pretrusted_peers:
        attestation_payload = generate_trust_credential_with_swe_and_auditor_role(
            src_address=peer,
            dest_address=trusted_peer_id,
            swe_trust_level=1,
            auditor_trust_level=1    
        )
        attestation_payload_list.append(attestation_payload)

    # 2. Malicious peer then endorses a untrustworthy User
    attestation_payload = generate_trust_credential_with_swe_and_auditor_role(
        src_address=trusted_peer_id,
        snap_checksum=bad_peer_id,
        swe_trust_level=1,
        auditor_trust_level=1    
    )
    attestation_payload_list.append(attestation_payload)

    return attestation_payload_list


if __name__ == "__main__":
    mock_trusted_peer_id = 'trusted_peer_id_1'
    mock_bad_peer_id = 'bad_peer_id_1'
    mock_pretrusted_peers = [
        'pretrusted_peer_id_1',
        'pretrusted_peer_id_2',
        'pretrusted_peer_id_3',
    ]

    attestation_payload_list = execute(
        trusted_peer_id=mock_trusted_peer_id,
        bad_peer_id=mock_bad_peer_id,
        pretrusted_peers=mock_pretrusted_peers
    )

    for attestation_payload in attestation_payload_list:
        print(attestation_payload)
