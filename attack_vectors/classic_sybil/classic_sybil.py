import json

from datetime import datetime, timedelta, timezone
from utils.common import read_network_input, generate_network_events_file, generate_trust_credential_with_auditor_role, generate_dispute_snap_payload, generate_endorse_snap_payload


def assign_auditor_trust_to_sybils(start_unix_timestamp, sybil_origin, sybils, interval):
    print(f"Sybil origin ({sybil_origin}) assigning auditor TrustCredentials to {len(sybils)} sybils")
    current_unix_timestamp = start_unix_timestamp
    all_sybil_trust_credentials_payloads = []

    for sybil in sybils:
        payload = {
            "0": current_unix_timestamp,
            "1": generate_trust_credential_with_auditor_role(
                src_address=sybil_origin,
                dest_address=sybil["address"],
                auditor_trust_level=1
            )
        }
        all_sybil_trust_credentials_payloads.append(payload)
        current_unix_timestamp += interval
    
    return current_unix_timestamp, all_sybil_trust_credentials_payloads


def downvote_trustworthy_snap(start_unix_timestamp, sybils, target_snap_checksum, interval):
    print(f"{len(sybils)} sybils downvoting trustworthy snap with checksum: {target_snap_checksum}")
    current_unix_timestamp = start_unix_timestamp
    dispute_trustworthy_snap_payloads = []

    for sybil in sybils:
        payload = {
            "0": current_unix_timestamp,
            "1": generate_dispute_snap_payload(
                src_address=sybil["address"],
                snap_checksum=target_snap_checksum,
                reasons={}
            )
        }
        dispute_trustworthy_snap_payloads.append(payload)
        current_unix_timestamp += interval

    return current_unix_timestamp, dispute_trustworthy_snap_payloads


def upvote_malicious_snap(start_unix_timestamp, sybils, target_snap_checksum, interval):
    print(f"{len(sybils)} sybils upvoting malicious snap with checksum: {target_snap_checksum}")
    current_unix_timestamp = start_unix_timestamp
    endorse_malicious_snap_payloads = []

    for sybil in sybils:
        payload = {
            "0": current_unix_timestamp,
            "1": generate_endorse_snap_payload(
                src_address=sybil["address"],
                snap_checksum=target_snap_checksum,
                reasons=[]
            )
        }
        endorse_malicious_snap_payloads.append(payload)
        current_unix_timestamp += interval

    return current_unix_timestamp, endorse_malicious_snap_payloads


def execute_sybil_attack(start_unix_timestamp, sybils, target_snap_checksum, interval, attack_type):
    current_unix_timestamp = start_unix_timestamp

    if attack_type == 'DOWNVOTE':
        next_timestamp, dispute_trustworthy_snap_payloads = downvote_trustworthy_snap(
            start_unix_timestamp=current_unix_timestamp,
            sybils=sybils, 
            target_snap_checksum=target_snap_checksum,
            interval=interval
        )

        return next_timestamp, dispute_trustworthy_snap_payloads

    elif attack_type == 'UPVOTE':
        next_timestamp, endorse_malicious_snap_payloads = upvote_malicious_snap(
            start_unix_timestamp=next_timestamp,
            sybils=sybils, 
            target_snap_checksum=current_unix_timestamp,
            interval=interval
        )

        return next_timestamp, endorse_malicious_snap_payloads

    else:
        raise NameError("invalid attack vector")


def init_classic_sybil_without_auditor_trust(start_unix_timestamp, target_snap_checksum, attack_type, interval):
    print(f"start_timestamp: {start_unix_timestamp}")

    # intialise sybil network participants
    sybil_network_participants = read_network_input("network_inputs/network_participants/sybil_network_participants.json")["eoas"]

    next_timestamp, sybil_snap_payloads = execute_sybil_attack(
        start_unix_timestamp=start_unix_timestamp,
        sybils=sybil_network_participants,
        target_snap_checksum=target_snap_checksum,
        interval=interval,
        attack_type=attack_type
    )

    sybil_scenario_payloads = sybil_snap_payloads
    generate_network_events_file(
        payloads=sybil_scenario_payloads,
        filename="sybils_without_auditor_trust.json"
    )
    print(f"next_timestamp: {next_timestamp}\n")

    return next_timestamp, sybil_scenario_payloads


def init_classic_sybil_with_auditor_trust(start_unix_timestamp, sybil_origin, target_snap_checksum, attack_type, interval):
    print(f"start_timestamp: {start_unix_timestamp}")

    # intialise sybil network participants
    sybil_network_participants = read_network_input("network_inputs/network_participants/sybil_network_participants.json")["eoas"]

    # sybil origin gives auditor TrustCredentials to the sybil network participants
    next_timestamp, all_sybil_trust_credentials_payloads = assign_auditor_trust_to_sybils(
        start_unix_timestamp=start_unix_timestamp,
        sybil_origin=sybil_origin,
        sybils=sybil_network_participants,
        interval=interval
    )

    next_timestamp, sybil_snap_payloads = execute_sybil_attack(
        start_unix_timestamp=next_timestamp,
        sybils=sybil_network_participants,
        target_snap_checksum=target_snap_checksum,
        interval=interval,
        attack_type=attack_type
    )

    sybil_scenario_payloads = all_sybil_trust_credentials_payloads + sybil_snap_payloads
    generate_network_events_file(
        payloads=sybil_scenario_payloads,
        filename="sybils_with_auditor_trust.json"
    )
    print(f"next_timestamp: {next_timestamp}\n")

    return next_timestamp, sybil_scenario_payloads
