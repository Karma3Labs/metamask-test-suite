import json

import sys
sys.path.append('..')

from utils.common import generate_trust_credential_with_swe_role, generate_trust_credential_with_auditor_role, generate_trust_credential_with_swe_and_auditor_role, generate_trust_credential_with_honesty_role


"""
permissible trust values: 1, 0, -1
"""
if __name__ == "__main__":
    ta_1 = "0x00000000000000000000000000000000000000A1"
    eoa_1 = "0x0000000000000000000000000000000000000001"
    eoa_2 = "0x0000000000000000000000000000000000000002"
    eoa_3 = "0x0000000000000000000000000000000000000002"
    
    test_generate_trust_credential_with_swe_role = generate_trust_credential_with_swe_role(
        src_address=ta_1,
        dest_address=eoa_1,
        swe_trust_level=1
    )
    print(json.dumps(test_generate_trust_credential_with_swe_role, indent=2))

    test_generate_trust_credential_with_auditor_role = generate_trust_credential_with_auditor_role(
        src_address=ta_1,
        dest_address=eoa_1,
        auditor_trust_level=1
    )
    print(json.dumps(test_generate_trust_credential_with_auditor_role, indent=2))

    test_generate_trust_credential_with_swe_and_auditor_role = generate_trust_credential_with_swe_and_auditor_role(
        src_address=ta_1,
        dest_address=eoa_1,
        swe_trust_level=1,
        auditor_trust_level=1
    )
    print(json.dumps(test_generate_trust_credential_with_swe_and_auditor_role, indent=2))

    test_generate_trust_credential_with_honesty_role = generate_trust_credential_with_honesty_role(
        src_address=ta_1,
        dest_address=eoa_1,
    )
    print(json.dumps(test_generate_trust_credential_with_honesty_role, indent=2))
