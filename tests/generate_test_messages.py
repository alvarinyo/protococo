#!/usr/bin/env python3
"""Generate test messages for golden tests"""

# Valid messages for different message types
TEST_MESSAGES = {
    "binary_data_packet_1byte": {
        "valid": "0223050048656C6C6F4BB703",
        "description": "Valid binary data packet with 'Hello' payload"
    },
    "mime_binary_data_packet": {
        "valid": "0223140D746578742F706C61696E0500000048656C6C6FBBBB03",
        "description": "Valid MIME binary data packet with text/plain, 'Hello' content"
    },
}

if __name__ == "__main__":
    for msg_type, data in TEST_MESSAGES.items():
        print(f"{msg_type}: {data['valid']}")
        print(f"  Description: {data['description']}")
        print()
