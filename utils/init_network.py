import random
from datetime import datetime, timedelta, timezone
from utils.common import read_network_input, generate_network_events_file, generate_trust_credential_with_swe_role, generate_trust_credential_with_auditor_role, generate_trust_credential_with_swe_and_auditor_role, generate_endorse_snap_payload, generate_dispute_snap_payload


"""
def assign_trust_credentials(start_time, trust_anchor, participants):
    current_utc_timestamp = start_time

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=0)
    a = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_role(
            src_address=trust_anchor["address"],
            dest_address=participants[0]["address"],
            swe_trust_level=1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    b = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_role(
            src_address=trust_anchor["address"],
            dest_address=participants[1]["address"],
            swe_trust_level=0
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    c = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_role(
            src_address=trust_anchor["address"],
            dest_address=participants[2]["address"],
            swe_trust_level=-1
        )
    }
    
    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    d = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[3]["address"],
            auditor_trust_level=1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    e = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[4]["address"],
            auditor_trust_level=0
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    f = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[5]["address"],
            auditor_trust_level=-1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    g = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[6]["address"],
            swe_trust_level=1,
            auditor_trust_level=1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    h = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[7]["address"],
            swe_trust_level=1,
            auditor_trust_level=0
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    i = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[8]["address"],
            swe_trust_level=1,
            auditor_trust_level=-1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    j = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[9]["address"],
            swe_trust_level=0,
            auditor_trust_level=1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    k = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[10]["address"],
            swe_trust_level=0,
            auditor_trust_level=0
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    l = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[11]["address"],
            swe_trust_level=0,
            auditor_trust_level=-1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    m = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[12]["address"],
            swe_trust_level=-1,
            auditor_trust_level=1
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    n = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[13]["address"],
            swe_trust_level=-1,
            auditor_trust_level=0
        )
    }

    current_utc_timestamp = current_utc_timestamp + timedelta(seconds=10)
    o = {
        "timestamp": current_utc_timestamp.isoformat(),
        "attestation": generate_trust_credential_with_swe_and_auditor_role(
            src_address=trust_anchor["address"],
            dest_address=participants[14]["address"],
            swe_trust_level=-1,
            auditor_trust_level=-1
        )
    }

    return [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o]


def assign_status_credentials(start_time, eoa, snaps):
    current_utc_timestamp = start_time

    snap_status_credentials = []
    for snap in snaps:
        a = {
            "timestamp": current_utc_timestamp.isoformat(),
            "attestation": generate_endorse_snap_payload(
                src_address=eoa["address"],
                snap_checksum=snap["checksum"],
                reasons=[]
            )
        }
        snap_status_credentials.append(a)

        b = {
            "timestamp": current_utc_timestamp.isoformat(),
            "attestation": generate_dispute_snap_payload(
                src_address=eoa["address"],
                snap_checksum=snap["checksum"],
                reasons=[]
            )
        }
        snap_status_credentials.append(b)
    
    return snap_status_credentials

     

def init_network(start_timestamp, trust_anchors, participants, snaps):
    print(f"\nstart_timestamp: {start_timestamp}")
    print(f"Generating attestations to initialise network for: \n{len(trust_anchors)} Trust Anchors, \n{len(participants)} EOAs,\n{len(snaps)} Snaps")
    current_timestamp = start_timestamp
    all_assign_trust_credentials_payload = []
    all_assign_status_credentials_payload = []

    # assign TrustCredential from TA to EOA
    # 1. auditor (-1, 1)
    # 2. non-auditors
    # 50 EOAs => param: int = 7 => 50C7 (random)
    # 7 TA -> EOAs => auditor (rndom?)
    for trust_anchor in trust_anchors: 
        trust_credentials_payloads = assign_trust_credentials(
            start_time=current_timestamp,
            trust_anchor=trust_anchor,
            participants=participants
        )
        all_assign_trust_credentials_payload += trust_credentials_payloads
        current_timestamp = datetime.fromisoformat(all_assign_trust_credentials_payload[-1]["timestamp"])
        current_timestamp += timedelta(seconds=10)

    # assign StatusCredential from EOA to snaps
    for participant in participants:
        status_credentials_payloads = assign_status_credentials(
            start_time=current_timestamp,
            eoa=participant,
            snaps=snaps
        )
        all_assign_status_credentials_payload += status_credentials_payloads
        current_timestamp = datetime.fromisoformat(all_assign_status_credentials_payload[-1]["timestamp"])
        current_timestamp += timedelta(seconds=10)
    
    init_network_payload = all_assign_trust_credentials_payload + all_assign_status_credentials_payload

    return current_timestamp, init_network_payload

"""

def assign_auditor_trust_credentials(start_unix_timestamp, trust_anchor, eoas, trust_level, interval):
    current_unix_timestamp = start_unix_timestamp
    auditor_trust_credentials_attestation_payloads = []

    for eoa in eoas:
        payload = {
            "0": current_unix_timestamp,
            "1": generate_trust_credential_with_auditor_role(
                src_address=trust_anchor["address"],
                dest_address=eoa["address"],
                auditor_trust_level=trust_level
            )
        }
        auditor_trust_credentials_attestation_payloads.append(payload)
        current_unix_timestamp += interval
    
    return current_unix_timestamp, auditor_trust_credentials_attestation_payloads
    

def assign_snap_status_credentials(start_unix_timestamp, eoa, snaps, status, interval):
    current_unix_timestamp = start_unix_timestamp
    snaps_status_credentials_attestation_payloads = []


    for snap in snaps:
        if status == 0:
            val = generate_endorse_snap_payload(
                src_address=eoa["address"],
                snap_checksum=snap["checksum"],
                reasons={}
            )
        elif status == 1:
            val = generate_dispute_snap_payload(
                src_address=eoa["address"],
                snap_checksum=snap["checksum"],
                reasons={}
            )
        else:
            raise TypeError(f"unsupported status: {status}")

        payload = {
            "0": current_unix_timestamp,
            "1": val
        }
        snaps_status_credentials_attestation_payloads.append(payload)
        current_unix_timestamp += interval
    
    return current_unix_timestamp, snaps_status_credentials_attestation_payloads


def init_initial_network_state(start_unix_timestamp):
    current_unix_timestamp = start_unix_timestamp
    init_network_attestations = []

    # special eoas with the authority to issue highly-credible attestations
    trust_anchors = read_network_input("network_inputs/trust_anchors/initial_trust_anchors.json")["trust_anchors"]

    # list of eoas trusted by the trust anchors to be an auditor
    initial_trusted_auditors = read_network_input("network_inputs/network_participants/initial_trusted_auditors.json")["eoas"]
    # list of eoas NOT trusted by the trust anchors to be an auditor
    initial_untrusted_auditors = read_network_input("network_inputs/network_participants/initial_untrusted_auditors.json")["eoas"]
    # list of eoas not known by the trust anchors
    initial_non_auditors = read_network_input("network_inputs/network_participants/initial_non_auditors.json")["eoas"]

    # list of snaps that:
    # 1. trusted eoas will endorse
    # 2. untrusted eoas will dispute
    initial_honest_snaps = read_network_input("network_inputs/snaps/initial_honest_snaps.json")["snaps"]
    # list of snaps that:
    # 1. trusted eoas will endorse
    # 2. untrusted eoas will dispute
    initial_malicious_snaps = read_network_input("network_inputs/snaps/initial_malicious_snaps.json")["snaps"]


    # Phase 1: network initialisation
    # - Phase 1.1: issuance of TrustCredential attestations from TA to EOAs
    #   - Phase 1.1.1: TA issue (auditor, 1) TC attestations to trusted EOAs
    #   - Phase 1.1.2: TA issue (auditor, -1) TC attestations to untrusted EOAs
    # - Phase 1.2: issuance of StatusCredential attestations from EOAs to Snaps
    #   - Phase 1.2.1: trusted EOAs issue "Endorse" SC to honest snaps
    #   - Phase 1.2.2: trusted EOAs issue "Disputed" SC to malicious snaps
    #   - Phase 1.2.3: untrusted EOAs issue "Disputed" SC to honest snaps
    #   - Phase 1.2.4: untrusted EOAs issue "Endorsed" SC to malicious snaps
    #   - Phase 1.2.5: unknown EOAs issue "" SC to honest snaps ==> to clarify
    #   - Phase 1.2.6: unknown EOAs issue "" SC to malicious snaps ==> to clarify

    for trust_anchor in trust_anchors:
        # 1.1.1: TA ==(auditor, 1)==> trusted EOAs
        next_unix_timestamp, trusted_auditors_attestations = assign_auditor_trust_credentials(
            start_unix_timestamp=current_unix_timestamp,
            trust_anchor=trust_anchor,
            eoas=initial_trusted_auditors,
            trust_level=1,
            interval=10
        )
        init_network_attestations += trusted_auditors_attestations

        # 1.1.2: TA ==(auditor, -1)==> untrusted EOAs
        next_unix_timestamp, untrusted_auditors_attestations = assign_auditor_trust_credentials(
            start_unix_timestamp=next_unix_timestamp,
            trust_anchor=trust_anchor,
            eoas=initial_untrusted_auditors,
            trust_level=-1,
            interval=10
        )
        init_network_attestations += untrusted_auditors_attestations

        current_unix_timestamp = next_unix_timestamp

    for trusted_auditor in initial_trusted_auditors:
        # 1.2.1: trusted EOAs ==(endorse)==> honest_snap
        next_unix_timestamp, trusted_auditors_honest_snap_attestations = assign_snap_status_credentials(
            start_unix_timestamp=current_unix_timestamp,
            eoa=trusted_auditor,
            snaps=initial_honest_snaps,
            status=0,
            interval=10
        )
        init_network_attestations += trusted_auditors_honest_snap_attestations

        # 1.2.2: trusted EOAs ==(dispute)==> malicious_snap
        next_unix_timestamp, trusted_auditors_malicious_snap_attestations = assign_snap_status_credentials(
            start_unix_timestamp=next_unix_timestamp,
            eoa=trusted_auditor,
            snaps=initial_malicious_snaps,
            status=1,
            interval=10
        )
        init_network_attestations += trusted_auditors_malicious_snap_attestations

        current_unix_timestamp = next_unix_timestamp

    for untrusted_auditor in initial_untrusted_auditors:
        # 1.2.3: untrusted EOAs ==(dispute)==> honest_snap
        next_unix_timestamp, untrusted_auditors_honest_snap_attestations = assign_snap_status_credentials(
            start_unix_timestamp=current_unix_timestamp,
            eoa=untrusted_auditor,
            snaps=initial_honest_snaps,
            status=1,
            interval=10
        )
        init_network_attestations += untrusted_auditors_honest_snap_attestations

        # 1.2.4: untrusted EOAs ==(endorse)==> malicious_snap
        next_unix_timestamp, untrusted_auditors_malicious_snap_attestations = assign_snap_status_credentials(
            start_unix_timestamp=next_unix_timestamp,
            eoa=untrusted_auditor,
            snaps=initial_malicious_snaps,
            status=0,
            interval=10
        )
        init_network_attestations += untrusted_auditors_malicious_snap_attestations

        current_unix_timestamp = next_unix_timestamp

    generate_network_events_file(
        payloads=init_network_attestations,
        filename="initial_network_state.json"
    )
    print(f"total number of attestations: {len(init_network_attestations)}")
    print(f"next_timestamp: {current_unix_timestamp}\n")

    return current_unix_timestamp, init_network_attestations
