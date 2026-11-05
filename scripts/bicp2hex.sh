#!/bin/bash
# Extract hex BICP frames from a remote target via bpftrace
#
# Usage: ./scripts/bicp2hex.sh [host]
#   host: SSH target (default: root@192.168.2.2)
#
# Examples:
#   ./scripts/bicp2hex.sh | python3 protococo.py find --cocofile=protocols/bicp/dl_256.coco --dissect --tree
#   ./scripts/bicp2hex.sh root@myboard | python3 protococo.py check dl_frame_256 --cocofile=protocols/bicp/dl_256.coco --tree

HOST="${1:-root@192.168.2.2}"

ssh "$HOST" "env BPFTRACE_STRLEN=200 ./trace_bicp.bt 4" | \
    grep --line-buffered -E '^[0-9]' | \
    awk '{print $NF; fflush()}' | \
    sed -u 's/\\x//g'
