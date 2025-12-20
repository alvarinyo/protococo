#!/bin/bash
# Extract raw hex from pcap files using tshark
# Usage: ./scripts/pcap2hex.sh <pcap_file> [packet_number] [count]
#
# Examples:
#   ./scripts/pcap2hex.sh capture.pcap                    # First packet
#   ./scripts/pcap2hex.sh capture.pcap 5                  # Packet #5
#   ./scripts/pcap2hex.sh capture.pcap 1 10               # Packets 1-10 (one per line)
#   ./scripts/pcap2hex.sh capture.pcap | protococo find   # Pipe to protococo

set -e

PCAP_FILE="${1:-}"
PACKET_NUM="${2:-1}"
COUNT="${3:-1}"

if [[ -z "$PCAP_FILE" ]]; then
    echo "Usage: $0 <pcap_file> [packet_number] [count]" >&2
    echo "  packet_number: 1-indexed packet to start from (default: 1)" >&2
    echo "  count: number of packets to extract (default: 1)" >&2
    exit 1
fi

if [[ ! -f "$PCAP_FILE" ]]; then
    echo "Error: File not found: $PCAP_FILE" >&2
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark not found. Install wireshark-cli or tshark." >&2
    exit 1
fi

# Use frame number filter for specific packet, or just -c for count from start
if [[ "$PACKET_NUM" -eq 1 ]]; then
    FILTER_ARGS="-c $COUNT"
else
    # For non-first packet, we need to use a display filter
    END_PACKET=$((PACKET_NUM + COUNT - 1))
    FILTER_ARGS="-Y frame.number>=$PACKET_NUM && frame.number<=$END_PACKET"
fi

# Extract hex using tshark -x, parse the hex dump format
tshark -r "$PCAP_FILE" $FILTER_ARGS -x 2>/dev/null | awk '
    /^[0-9a-f]{4}  / {
        # Each line starts with offset (4 hex chars), then 2 spaces, then hex bytes
        # Format: "0000  aa bb cc dd ..."
        # Extract bytes from columns 2-17 (16 bytes per line)
        hex = ""
        for (i = 2; i <= 17; i++) {
            if ($i ~ /^[0-9a-f]{2}$/) {
                hex = hex $i
            }
        }
        printf "%s", hex
    }
    /^$/ {
        # Empty line separates packets - print newline if we have output
        if (length(hex) > 0 || packet_started) {
            print ""
            packet_started = 0
        }
    }
    BEGIN { packet_started = 0 }
    /^[0-9a-f]{4}  / { packet_started = 1 }
' | grep -v '^$'
