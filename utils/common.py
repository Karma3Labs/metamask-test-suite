import json
import time
import csv


def add_seconds_to_unix_timestamp(curr_unix_timestamp, seconds):
    return int(curr_unix_timestamp) + seconds


def read_network_input(json_filename):
    with open(json_filename, 'r') as file:
        data = json.load(file)

    return data


def generate_network_events_file(payloads, filename):
    with open(filename, 'w') as file:
        json.dump(payloads, file, indent=2)


def generate_base_trust_credential_payload(src_address, dest_address):
    payload = {
        "type": "TrustCredential",
        "issuer": f"did:pkh:eip155:1:{src_address}",
        "credentialSubject": {
            "id": f"did:pkh:eip155:1:{dest_address}",
            "trustworthiness": []
        },
        "proof": {
            "signature": ""
        }
    }

    return payload


def add_software_security_role_to_trust_credential(trust_credential_payload, trust_level):
    role_details = {
        "scope": "software security",
        "level": trust_level,
        "reason": []
    }
    trust_credential_payload["credentialSubject"]["trustworthiness"].append(role_details)

    return trust_credential_payload


def add_software_development_role_to_trust_credential(trust_credential_payload, trust_level):
    role_details = {
        "scope": "software development",
        "level": trust_level,
        "reason": []
    }
    trust_credential_payload["credentialSubject"]["trustworthiness"].append(role_details)

    return trust_credential_payload


def add_honesty_role_to_trust_credential(trust_credential_payload):
    role_details = {
        "scope": "honesty",
        "level": -1, # always -1
        "reason": []
    }
    trust_credential_payload["credentialSubject"]["trustworthiness"].append(role_details)

    return trust_credential_payload


def generate_trust_credential_with_swe_role(src_address, dest_address, swe_trust_level):
    payload = generate_base_trust_credential_payload(
        src_address=src_address,
        dest_address=dest_address
    )

    payload_with_role = add_software_development_role_to_trust_credential(
        trust_credential_payload=payload,
        trust_level=swe_trust_level
    )

    return payload_with_role


def generate_trust_credential_with_auditor_role(src_address, dest_address, auditor_trust_level):
    payload = generate_base_trust_credential_payload(
        src_address=src_address,
        dest_address=dest_address
    )

    payload_with_role = add_software_security_role_to_trust_credential(
        trust_credential_payload=payload,
        trust_level=auditor_trust_level
    )

    return payload_with_role


def generate_trust_credential_with_honesty_role(src_address, dest_address,):
    payload = generate_base_trust_credential_payload(
        src_address=src_address,
        dest_address=dest_address
    )

    payload_with_role = add_honesty_role_to_trust_credential(
        trust_credential_payload=payload,
    )

    return payload_with_role


def generate_trust_credential_with_swe_and_auditor_role(src_address, dest_address, swe_trust_level, auditor_trust_level):
    payload = generate_base_trust_credential_payload(
        src_address=src_address,
        dest_address=dest_address
    )

    payload_with_role = add_software_security_role_to_trust_credential(
        trust_credential_payload=payload,
        trust_level=auditor_trust_level
    )

    payload_with_role = add_software_development_role_to_trust_credential(
        trust_credential_payload=payload_with_role,
        trust_level=swe_trust_level
    )

    return payload_with_role


def generate_base_status_credential_payload(src_address, snap_checksum):
    payload = {
        "type": "StatusCredential",
        "issuer": f"did:pkh:eth:{src_address}",
        "credentialSubject": {
            "id": f"snap://{snap_checksum}",
            "currentStatus": "",
            "statusReason": {},
        },
        "proof": {
            "signature": ""
        }
    }

    return payload


def generate_endorse_snap_payload(src_address, snap_checksum, reasons):
    payload = generate_base_status_credential_payload(
        src_address=src_address,
        snap_checksum=snap_checksum
    )
    payload["credentialSubject"]["currentStatus"] = "Endorsed"
    payload["credentialSubject"]["statusReason"] = reasons

    return payload


def generate_dispute_snap_payload(src_address, snap_checksum, reasons):
    payload = generate_base_status_credential_payload(
        src_address=src_address,
        snap_checksum=snap_checksum
    )
    payload["credentialSubject"]["currentStatus"] = "Disputed"
    payload["credentialSubject"]["statusReason"] = reasons

    return payload


def generate_input_csv_file(init_network_attestations_list: list, scenario_attestations_list: list, file_name: str):
    csv_rows = []

    current_unix_timestamp = int(time.time())
    for i, attestation in enumerate(init_network_attestations_list):
        attestation_type = 1 if attestation["type"] == 'StatusCredential' else 2
        timestamp = current_unix_timestamp
        seq_num = i+1
        # row = [seq_num, timestamp * 1000, attestation_type, attestation]
        row = f"{seq_num};{timestamp * 1000};{attestation_type};{attestation}\n"
        row = row.replace("'", '"')

        csv_rows.append(row)

        # increment timestamp
        current_unix_timestamp += 10

    current_unix_timestamp += 600
    for i, attestation in enumerate(scenario_attestations_list):
        attestation_type = 1 if attestation["type"] == 'StatusCredential' else 2
        timestamp = current_unix_timestamp
        seq_num = len(csv_rows)+i+1
        #row = [seq_num, timestamp * 1000, attestation_type, attestation]
        row = f"{seq_num};{timestamp * 1000};{attestation_type};{attestation}\n"
        row = row.replace("'", '"')

        csv_rows.append(row)

        # increment timestamp
        current_unix_timestamp += 10

    with open(file_name, 'w', newline='') as csv_file:
        #csv_writer = csv.writer(csv_file, delimiter=';')
        #csv_writer.writerows(csv_rows)
        for row in csv_rows:
            csv_file.write(row)
