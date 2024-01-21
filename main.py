import json

from datetime import datetime, timezone
import time

from attack_vectors.classic_sybil.classic_sybil import init_classic_sybil_with_auditor_trust, init_classic_sybil_without_auditor_trust
from utils.init_network import init_initial_network_state


"""
TA
EOA (X, Y, Z)
Snaps (A, B)

1.1 TA =TrustCredentials=> EOA 
- X = (auditor, 1)
- Y = (auditor, -1)
where count(X) > count(Y) 

1.2 EOA =StatusCredentials=> Snaps
XA_endorse = X endorse Snap A
XA_dispute = X dispute Snap A

YA_endorse = Y endorse Snap A
YA_dispute = Y dispute Snap A

ZA_endorse = Z endorse Snap A
ZA_dispute = Z dispute Snap A

For each snap, there will be 6 "groups" of attestation. What's the distribution?
"""
if __name__ == "__main__":
    # 1: init network state
    unix_start_time = int(time.time())

    next_unix_timestamp_after_init_network, initial_network_state = init_initial_network_state(
        start_unix_timestamp=unix_start_time
    )

    # 2.1: init upvote of malicious snap using sybils
    # 2.2: init downvote of trustworthy snap using sybils
    sybil_origin_address = "0x0000000000000000000000000000000000000001"
    honest_snap_checksum = "ALwZocaUEbDErtQAsybaudZDJq65a8AwlEFgkGUpmAQ="
    malicious_snap_checksum = "CLwZocaUEbDErtQAsybaudZDJq65a8AwlEFgkGUpmAQ="

    next_unix_timestamp_after_sybil_with_auditor_trust_attack, sybil_status_credentials = init_classic_sybil_with_auditor_trust(
        start_unix_timestamp=next_unix_timestamp_after_init_network,
        interval=10,
        sybil_origin=sybil_origin_address,
        target_snap_checksum=honest_snap_checksum,
        attack_type="DOWNVOTE",
        #target_snap_checksum=malicious_snap_checksum,
        #attack_type="UPVOTE"
    )

    #next_unix_timestamp_after_sybil_without_auditor_trust_attack, sybil_status_credentials = init_classic_sybil_without_auditor_trust(
    #    start_unix_timestamp=next_unix_timestamp_after_init_network,
    #    interval=10,
    #    target_snap_checksum=honest_snap_checksum,
    #    attack_type="DOWNVOTE",
    #    #target_snap_checksum=malicious_snap_checksum,
    #    #attack_type="UPVOTE"
    #)
