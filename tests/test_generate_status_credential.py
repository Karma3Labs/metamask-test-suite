import json

import sys
sys.path.append('..')

from utils.common import generate_endorse_snap_payload, generate_dispute_snap_payload


if __name__ == "__main__":
    eoa_1 = "0x0000000000000000000000000000000000000001"
    eoa_2 = "0x0000000000000000000000000000000000000002"
    snap_1 = "ALwZocaUEbDErtQAsybaudZDJq65a8AwlEFgkGUpmAQ="
    snap_2 = "BLwZocaUEbDErtQAsybaudZDJq65a8AwlEFgkGUpmAQ="
    
    test_generate_endorse_snap_payload = generate_endorse_snap_payload(
        src_address=eoa_1,
        snap_checksum=snap_1,
        reasons={}
    )
    print(json.dumps(test_generate_endorse_snap_payload, indent=2))

    test_generate_dispute_snap_payload = generate_dispute_snap_payload(
        src_address=eoa_2,
        snap_checksum=snap_2,
        reasons={}
    )
    print(json.dumps(test_generate_dispute_snap_payload, indent=2))
