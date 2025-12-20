#!/bin/bash
# Convert tcpdump -xx output to protococo input
# Usage: sudo tcpdump -xx ... | ./scripts/tcpdump2protococo.sh [--skip-eth] [--skip-sll] [--skip-ip]
#
# Example:
#   sudo tcpdump -i lo -c 1 -xx "udp port 12345" | ./scripts/tcpdump2protococo.sh --skip-eth
#   sudo tcpdump -i any -c 1 -xx "udp port 53" | ./scripts/tcpdump2protococo.sh --skip-sll

SKIP_ETH=0
SKIP_SLL=0
SKIP_IP=0
COCO_FILE=""
DISSECT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-eth) SKIP_ETH=1; shift ;;
        --skip-sll) SKIP_SLL=1; shift ;;
        --skip-ip) SKIP_IP=1; shift ;;
        --cocofile=*) COCO_FILE="${1#*=}"; shift ;;
        --dissect) DISSECT="--dissect --decode"; shift ;;
        *) shift ;;
    esac
done

# Read and accumulate hex from tcpdump output
HEX=""
while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*0x[0-9a-f]+:[[:space:]]+(.*) ]]; then
        hex_part="${BASH_REMATCH[1]}"
        hex_part=$(echo "$hex_part" | sed 's/  .*//' | tr -d ' ')
        HEX="${HEX}${hex_part}"
    fi
done

if [[ -z "$HEX" ]]; then
    exit 0
fi

# Calculate skip offset
SKIP=0
[[ $SKIP_ETH -eq 1 ]] && SKIP=$((SKIP + 28))  # 14 bytes = 28 hex chars
[[ $SKIP_SLL -eq 1 ]] && SKIP=$((SKIP + 32))  # 16 bytes = 32 hex chars (Linux cooked capture)
[[ $SKIP_IP -eq 1 ]] && SKIP=$((SKIP + 40))   # 20 bytes = 40 hex chars

if [[ $SKIP -gt 0 && ${#HEX} -gt $SKIP ]]; then
    HEX="${HEX:$SKIP}"
fi

if [[ -n "$COCO_FILE" ]]; then
    python3 protococo.py find "$HEX" --cocofile="$COCO_FILE" $DISSECT --format=multiline
else
    echo "$HEX"
fi
