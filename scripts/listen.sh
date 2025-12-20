#!/bin/bash
# Listen for network packets and analyze them with protococo
#
# Usage: ./scripts/listen.sh [options] [-- tcpdump_filter]
#
# Options:
#   -i, --interface IFACE   Network interface (default: any)
#   -c, --count N           Number of packets to capture (default: unlimited)
#   --cocofile FILE         Protococo rules file (required)
#   --skip-eth              Skip Ethernet header (14 bytes)
#   --skip-ip               Skip IP header (20 bytes)
#   --                      Separator for tcpdump filter expression
#
# Any other options are passed through to protococo (e.g., --tree, --decode, --dissect)
#
# Examples:
#   # Listen for ICMP packets on loopback
#   sudo ./scripts/listen.sh -i lo --cocofile=protocols/ip.coco --dissect --tree -- icmp
#
#   # Listen for UDP packets on any interface
#   sudo ./scripts/listen.sh --cocofile=protocols/ip.coco --tree --decode -- udp
#
#   # Capture 5 TCP packets
#   sudo ./scripts/listen.sh -i eth0 -c 5 --cocofile=protocols/ip.coco -- tcp

set -e

# Default values
INTERFACE="lo"
COUNT=""
COCO_FILE=""
SKIP_BYTES=0
SKIP_ETH=1  # Default to skipping Ethernet header
SKIP_SLL=0
SKIP_IP=0
DEBUG=0
PROTOCOCO_ARGS=()
TCPDUMP_FILTER=""

show_help() {
    cat << 'EOF'
Listen for network packets and analyze them with protococo

Usage: ./scripts/listen.sh [options] [-- tcpdump_filter]

Options:
  -i, --interface IFACE   Network interface (default: lo)
  -c, --count N           Number of packets to capture (default: unlimited)
  --cocofile FILE         Protococo rules file (required)
  --skip=N                Skip N bytes from start of packet
  --no-skip               Don't skip any link-layer header
  --skip-eth              Skip Ethernet header (14 bytes) - default
  --skip-sll              Skip Linux SLL header (16 bytes) - use with -i any
  --skip-ip               Skip IP header (20 bytes)
  --debug                 Show raw hex before processing (helps find correct skip value)
  -h, --help              Show this help message
  --                      Separator for tcpdump filter expression

Any other options are passed through to protococo (e.g., --tree, --decode, --dissect)

Examples:
  # Listen for DNS traffic with tree output (uses defaults: -i lo --skip-eth)
  sudo ./scripts/listen.sh --cocofile=protocols/ip.coco --dissect --tree --decode -- "udp port 53"

  # Listen for ICMP on eth0
  sudo ./scripts/listen.sh -i eth0 --cocofile=protocols/ip.coco --dissect --tree -- icmp

  # Listen on "any" interface (requires --skip-sll instead of --skip-eth)
  sudo ./scripts/listen.sh -i any --no-skip --skip-sll --cocofile=protocols/ip.coco --dissect -- tcp
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -c|--count)
            COUNT="$2"
            shift 2
            ;;
        --cocofile=*)
            COCO_FILE="${1#*=}"
            shift
            ;;
        --cocofile)
            COCO_FILE="$2"
            shift 2
            ;;
        --skip=*)
            SKIP_BYTES="${1#*=}"
            shift
            ;;
        --no-skip)
            SKIP_ETH=0
            SKIP_SLL=0
            shift
            ;;
        --skip-eth)
            SKIP_ETH=1
            shift
            ;;
        --skip-sll)
            SKIP_SLL=1
            shift
            ;;
        --skip-ip)
            SKIP_IP=1
            shift
            ;;
        --debug)
            DEBUG=1
            shift
            ;;
        --)
            shift
            TCPDUMP_FILTER="$*"
            break
            ;;
        -*)
            # Pass through to protococo
            PROTOCOCO_ARGS+=("$1")
            shift
            ;;
        *)
            # Assume it's part of tcpdump filter
            TCPDUMP_FILTER="$*"
            break
            ;;
    esac
done

# Validate required arguments
if [[ -z "$COCO_FILE" ]]; then
    echo "Error: --cocofile is required" >&2
    echo "Usage: $0 --cocofile=FILE [options] [-- tcpdump_filter]" >&2
    exit 1
fi

if [[ ! -f "$COCO_FILE" ]]; then
    echo "Error: Cocofile not found: $COCO_FILE" >&2
    exit 1
fi

# Build tcpdump command
TCPDUMP_CMD="tcpdump -i $INTERFACE -xx -l"
[[ -n "$COUNT" ]] && TCPDUMP_CMD="$TCPDUMP_CMD -c $COUNT"
[[ -n "$TCPDUMP_FILTER" ]] && TCPDUMP_CMD="$TCPDUMP_CMD $TCPDUMP_FILTER"

# Calculate skip offset (in hex chars = bytes * 2)
SKIP=$((SKIP_BYTES * 2))  # Custom skip in bytes
[[ $SKIP_ETH -eq 1 ]] && SKIP=$((SKIP + 28))  # 14 bytes = 28 hex chars
[[ $SKIP_SLL -eq 1 ]] && SKIP=$((SKIP + 32))  # 16 bytes = 32 hex chars (Linux cooked capture)
[[ $SKIP_IP -eq 1 ]] && SKIP=$((SKIP + 40))   # 20 bytes = 40 hex chars

# Find protococo.py location (relative to this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTOCOCO_DIR="$(dirname "$SCRIPT_DIR")"
PROTOCOCO="$PROTOCOCO_DIR/protococo.py"

if [[ ! -f "$PROTOCOCO" ]]; then
    echo "Error: protococo.py not found at $PROTOCOCO" >&2
    exit 1
fi

# Determine Python to use (preserve user's Python when running with sudo)
if [[ -n "$SUDO_USER" ]]; then
    # Running under sudo - use the original user's Python
    PYTHON="sudo -u $SUDO_USER python3"
else
    PYTHON="python3"
fi

echo "Listening on $INTERFACE${TCPDUMP_FILTER:+ for '$TCPDUMP_FILTER'}..."
echo "Press Ctrl+C to stop"
echo "---"

# Process packets
process_packet() {
    local hex="$1"

    if [[ -z "$hex" ]]; then
        return
    fi

    # Debug mode: show raw hex and help find the IP header
    if [[ $DEBUG -eq 1 ]]; then
        echo "Raw hex (${#hex} chars = $((${#hex}/2)) bytes):"
        echo "$hex"
        # Try to find IPv4 header (starts with 0x45 for standard 20-byte header)
        local pos=$(echo "$hex" | grep -bo "45" | head -1 | cut -d: -f1)
        if [[ -n "$pos" ]]; then
            echo "Possible IPv4 header at byte $((pos/2)) (hex position $pos)"
            echo "Try: --skip=$((pos/2))"
        fi
        echo "---"
        return
    fi

    # Apply skip offset
    if [[ $SKIP -gt 0 && ${#hex} -gt $SKIP ]]; then
        hex="${hex:$SKIP}"
    fi

    # Run protococo
    $PYTHON "$PROTOCOCO" find "$hex" --cocofile="$COCO_FILE" "${PROTOCOCO_ARGS[@]}"
    echo "---"
}

# Read tcpdump output and accumulate hex for each packet
$TCPDUMP_CMD 2>/dev/null | {
    HEX=""
    PACKET_NUM=0

    while IFS= read -r line; do
        # Check if this is a new packet header (timestamp line)
        if [[ "$line" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
            # Process previous packet if we have one
            if [[ -n "$HEX" ]]; then
                PACKET_NUM=$((PACKET_NUM + 1))
                echo "[Packet #$PACKET_NUM]"
                process_packet "$HEX"
            fi
            HEX=""
        # Check if this is a hex line (starts with 0x followed by offset)
        elif [[ "$line" =~ ^[[:space:]]*0x[0-9a-f]+:[[:space:]]+(.*) ]]; then
            hex_part="${BASH_REMATCH[1]}"
            # Remove ASCII representation at the end and spaces
            hex_part=$(echo "$hex_part" | sed 's/  .*//' | tr -d ' ')
            HEX="${HEX}${hex_part}"
        fi
    done

    # Process last packet
    if [[ -n "$HEX" ]]; then
        PACKET_NUM=$((PACKET_NUM + 1))
        echo "[Packet #$PACKET_NUM]"
        process_packet "$HEX"
    fi
}
