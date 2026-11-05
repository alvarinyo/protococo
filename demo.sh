#!/bin/bash

# Protococo Presentation: Designing the Internet
# Usage: ./demo.sh [slide_number]
#   ./demo.sh        - Run full presentation
#   ./demo.sh 1      - Run slide 1
#   ./demo.sh 14     - Run slide 14

DEMO_DIR="/tmp/protococo_demo"
PROTOCOCO="python3 $(dirname "$0")/protococo.py"
FAST_MODE=false
TMUX_AUTO_SCROLL=false

# Colors
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
YELLOW=$'\033[1;33m'
MAGENTA=$'\033[0;35m'
RED=$'\033[0;31m'
BOLD=$'\033[1m'
NC=$'\033[0m'

# Setup demo directory
setup() {
    mkdir -p "$DEMO_DIR"
}

# Clear screen and scrollback buffer
clear_screen() {
    # Try multiple methods for maximum compatibility
    printf '\033c'                          # Full terminal reset
    printf '\033[3J\033[H\033[2J'           # Clear scrollback + screen
    tput clear 2>/dev/null || true          # Terminfo clear (fallback)
}

# Move cursor to top of screen (used after printing long slides)
move_to_top() {
    printf '\033[H'                         # Move cursor to home (top-left)
}

# Auto-scroll in tmux: enter copy mode and go to top
tmux_auto_scroll() {
    if [ "$TMUX_AUTO_SCROLL" = true ] && [ -n "$TMUX" ]; then
        tmux copy-mode
        tmux send-keys -X history-top
        tmux send-keys -X bottom-line  # Move cursor to bottom of screen (like L)
    fi
}

# Wait for 'j' (next) or 'k' (previous) key - just waits, doesn't print prompt
# Returns: 1 for next, -1 for previous
next() {
    while true; do
        read -rsn1 key
        if [[ $key == "j" ]]; then
            return 1
        elif [[ $key == "k" ]]; then
            return 0
        fi
    done
}

# Helper to display .coco file with syntax highlighting
show_file() {
    local file="$1"
    local filename=$(basename "$file")
    echo -e "\n${GREEN}${BOLD}File: ${filename}${NC}\n"
    batcat --style=plain --paging=never "$file"
    echo ""
}

# Helper to wait for Enter key
wait_enter() {
    if [ "$FAST_MODE" = false ]; then
        echo -e "\n${MAGENTA}${BOLD}Press Enter to continue...${NC}"
        read -r
    fi
}

# Helper to pause after showing file (only in non-fast mode)
pause_after_file() {
    if [ "$FAST_MODE" = false ]; then
        next
    fi
}

# Helper to run a command
run_cmd() {
    echo -e "\n${BLUE}${BOLD}$ $1${NC}"
    wait_enter
    eval "$1"
}

# Show slide progress indicator
show_slide_progress() {
    local current=$1
    local total=$2
    local slide_name=$3
    echo -en "\n${CYAN}[${slide_name} - ${current}/${total}]${NC}"
}

###########################################
# PRESENTATION SLIDES
###########################################

slide_title() {
    clear_screen
    cat << 'EOF'

    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║         DESIGNING THE INTERNET: A Protocol-as-Code Journey   ║
    ║                                                              ║
    ║              How we built the Ethernet/IP/TCP stack          ║
    ║                    using the protococo DSL                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝

EOF

}

slide0() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Traditional Protocol Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Problem:${NC} How do we specify network protocols?

${CYAN}${BOLD}Traditional Approach: RFCs in English${NC}
  • RFC 894: "An Ethernet frame contains..."
  • RFC 791: "The version field is 4 bits..."
  • ${RED}Ambiguous natural language${NC}
  • ${RED}Not machine-readable${NC}
  • ${RED}Separate from implementation${NC}

${BOLD}Result: Protocol Definition ≠ Protocol Implementation${NC}
         ↓
  Implementation bugs, interoperability issues, drift over time

${YELLOW}If only there was a better way...${NC}

EOF

}

slide0_5() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  Enter Protocol-as-Code${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Idea:${NC} Specify protocols in unambiguous, executable language

${YELLOW}${BOLD}Key Insight:${NC}
  The .coco file ${BOLD}IS${NC} the protocol specification
  (not a representation of a spec written elsewhere)

${CYAN}${BOLD}Single Source of Truth:${NC}
  ✓ Unambiguous syntax (no English interpretation needed)
  ✓ Machine-readable and executable
  ✓ Definition = Implementation = Documentation

${GREEN}${BOLD}Let's design the Internet stack using this approach...${NC}

EOF

}

slide25() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  Protococo vs Wireshark Dissectors${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Wireshark Dissector (Lua):${NC} Imperative, tell computer HOW
${YELLOW}
function proto.dissector(buffer, pinfo, tree)
  local offset = 0
  tree:add(f_dst_mac, buffer(offset, 6))
  offset = offset + 6  -- Manual tracking!
  tree:add(f_src_mac, buffer(offset, 6))
end${NC}

${CYAN}${BOLD}Protococo (.coco):${NC} Declarative, tell computer WHAT
${GREEN}
message ethernet_header {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
}${NC}

${BOLD}Key Differences:${NC}
  ${RED}Wireshark${NC}           →  ${GREEN}Protococo${NC}
  One-way (dissect)    →  Bi-directional (parse + create + validate)
  Tool-specific        →  Universal (generates dissectors + more)
  Manual offsets       →  Automatic calculation

${CYAN}${BOLD}Protococo generates dissectors, but it's much more:${NC}
  ✓ Validate packets  ✓ Identify messages  ✓ Create messages
  ✓ Generate tools    ✓ Single source of truth

EOF

}

slide1() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  Designing Layer 2 - The Data Link Layer${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Design Challenge:${NC} We need to send data between computers on a local network.

${YELLOW}${BOLD}Hardware Constraints:${NC}
  • Network cards only understand MAC addresses
  • MAC addresses are 6 bytes long
  • Each frame needs source and destination

${YELLOW}If only we could design a protocol that captures these requirements...${NC}

EOF

}

slide2() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Enter protococo${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} A clear, declarative protocol specification

EOF

    cat > "$DEMO_DIR/slide2.coco" << 'EOF'
version 1.0
endian be

message ethernet_header {
  bytes dst_mac[6]
  bytes src_mac[6]
}
EOF

    show_file "$DEMO_DIR/slide2.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Clear field definitions
  ✓ Fixed sizes (6 bytes each)
  ✓ Big-endian byte order by default
  ✓ Machine-readable specification

${BOLD}${GREEN}Let's create a message:${NC}

${CYAN}Command: protococo create --from-json=<file> --cocofile=<spec>${NC}
  • create: Generate hex message from field values
  • --from-json: Provide field values via JSON file
  • --cocofile: Specify the protocol definition file

EOF

    cat > "$DEMO_DIR/slide2.json" << 'EOF'
{
  "message_name": "ethernet_header",
  "message_fields": [
    {"field_name": "dst_mac", "value": "ffffffffffff"},
    {"field_name": "src_mac", "value": "0040059fb1f3"}
  ]
}
EOF

    echo -e "${YELLOW}JSON recipe (slide2.json):${NC}"
    batcat --style=plain --paging=never "$DEMO_DIR/slide2.json"
    echo ""

    run_cmd "$PROTOCOCO create --from-json=$DEMO_DIR/slide2.json --cocofile=$DEMO_DIR/slide2.coco"

}

slide3() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Readability Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} ${CYAN}ffffffffffff0040059fb1f3${NC} is not human-friendly.

When debugging network issues, we need to see MAC addresses like:
  • ${GREEN}ff:ff:ff:ff:ff:ff${NC} (broadcast)
  • ${GREEN}00:40:05:9f:b1:f3${NC} (actual address)

Let's validate a raw hex message:

${CYAN}Command: protococo check <message_name> <hex_string> --tree${NC}
  • check: Validate hex string against a specific message type
  • --tree: Display fields as tree structure with box-drawing characters

EOF

    run_cmd "$PROTOCOCO check ethernet_header ffffffffffff0040059fb1f3 --cocofile=$DEMO_DIR/slide2.coco --tree"

    echo -e "\n${RED}${BOLD}Problem: The MAC addresses are hard to read!${NC}"

    echo -e "\n${YELLOW}If only there was a way to make hex dumps human-readable without losing precision...${NC}"

}

slide4() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Display Formatters${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} Display formatters for human-readable output

EOF

    cat > "$DEMO_DIR/slide4.coco" << 'EOF'
version 1.0
endian be

message ethernet_header {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
}
EOF

    show_file "$DEMO_DIR/slide4.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Now let's check the same message with formatters:${NC}

${CYAN}New flag: --decode${NC}
  • --decode: Apply display formatters (MAC as aa:bb:cc, IP as 192.168.1.1, etc.)

EOF

    run_cmd "$PROTOCOCO check ethernet_header ffffffffffff0040059fb1f3 --cocofile=$DEMO_DIR/slide4.coco --decode --tree"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Raw storage stays as bytes
  ✓ Human-readable display formatting
  ✓ Debug output shows: ${GREEN}dst_mac: ff:ff:ff:ff:ff:ff${NC}
  ✓ Validation still works on raw bytes

EOF

}

slide5() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Payload Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} Ethernet can carry different types of payloads:

  • ${CYAN}IPv4 packets${NC}  (0x0800)
  • ${CYAN}ARP packets${NC}   (0x0806)
  • ${CYAN}VLAN-tagged frames${NC}     (0x8100)
  • ${CYAN}IPv6 packets${NC}  (0x86DD)

${YELLOW}If only there was a way to identify what comes next and handle multiple payload types cleanly...${NC}

EOF

}

slide6() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Enums as Discriminators${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} Use enums for type-safe discriminators

EOF

    cat > "$DEMO_DIR/slide6.coco" << 'EOF'
version 1.0
endian be

enum EtherType : u16 {
  IPV4 = 0x0800,
  ARP = 0x0806,
  VLAN = 0x8100,
  IPV6 = 0x86DD
}

message ethernet_header {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
  EtherType ethertype
}
EOF

    show_file "$DEMO_DIR/slide6.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Check a message with IPv4 ethertype (0x0800):${NC}

EOF

    run_cmd "$PROTOCOCO check ethernet_header ffffffffffff0040059fb1f30800 --cocofile=$DEMO_DIR/slide6.coco --decode --tree"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Type-safe discriminator
  ✓ Validation (only valid EtherType values accepted)
  ✓ Human-readable output: ${GREEN}EtherType.IPV4${NC} instead of ${CYAN}2048${NC}

EOF

}

slide7() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Polymorphism Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} The payload after EtherType should be parsed differently:

  • If ${CYAN}EtherType.IPV4${NC} → parse as IPv4 packet
  • If ${CYAN}EtherType.ARP${NC}  → parse as ARP packet
  • If ${CYAN}EtherType.VLAN${NC} → parse as VLAN frame
  • Otherwise          → just raw bytes

${YELLOW}If only there was a way to dispatch on discriminator values...${NC}

EOF

}

slide8() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Pattern Matching${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} Pattern matching for polymorphic dispatch

EOF

    cat > "$DEMO_DIR/slide8.coco" << 'EOF'
version 1.0
endian be

enum EtherType : u16 {
  IPV4 = 0x0800,
  ARP = 0x0806
}

message ethernet_frame {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
  EtherType ethertype

  bytes payload[] match ethertype {
    EtherType.IPV4 -> ipv4_stub ip
    EtherType.ARP -> arp_stub arp
    _ -> {}
  }
}

message ipv4_stub {
  u8 version_ihl
  u8 dscp
}

message arp_stub {
  u16 hw_type
  u16 proto_type
}
EOF

    show_file "$DEMO_DIR/slide8.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Check an IPv4 packet:${NC}

${CYAN}Command: protococo find <hex_string> --dissect${NC}
  • find: Identify which message type(s) match the hex string
  • --dissect: Show field dissection (not just message name)

EOF

    run_cmd "$PROTOCOCO find ffffffffffff0040059fb1f3080045000000 --cocofile=$DEMO_DIR/slide8.coco --dissect --tree --decode"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Polymorphic payload dispatch
  ✓ Type-specific parsing for each branch
  ✓ Fallback to raw bytes
  ✓ Field names for each layer (${GREEN}ip${NC}, ${GREEN}arp${NC})

EOF

}

slide9() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Protocol Chain Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} When debugging, we want to see the full protocol stack:

  • ${GREEN}[ethernet:vlan:ip:tcp]${NC}
  • Not just ${CYAN}[tcp_segment]${NC}

${YELLOW}If only there was a way to distinguish protocol layers from regular message types...${NC}

EOF

}

slide10() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Layer Modifier${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} Mark protocol layers with ${CYAN}layer${NC} keyword

Notice the distinction:
  • ${GREEN}message ethernet_header${NC} → regular data structure (NOT in chain)
  • ${GREEN}layer message ethernet_frame${NC} → protocol layer (IN chain)
  • ${GREEN}layer message ipv4_stub${NC} → protocol layer (IN chain)

EOF

    cat > "$DEMO_DIR/slide10.coco" << 'EOF'
version 1.0
endian be

enum EtherType : u16 {
  IPV4 = 0x0800,
  ARP = 0x0806
}

message ethernet_header {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
  EtherType ethertype
}

layer message ethernet_frame {
  ethernet_header header

  bytes payload[] match header.ethertype {
    EtherType.IPV4 -> ipv4_stub ip
    EtherType.ARP -> arp_stub arp
    _ -> {}
  }
}

layer message ipv4_stub {
  u8 version_ihl
  u8 dscp
}

layer message arp_stub {
  u16 hw_type
  u16 proto_type
}
EOF

    show_file "$DEMO_DIR/slide10.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}See the protocol chain in find output:${NC}

${CYAN}Without --dissect, find shows just the protocol chain:${NC}

EOF

    run_cmd "$PROTOCOCO find ffffffffffff0040059fb1f3080045000000 --cocofile=$DEMO_DIR/slide10.coco"

    cat << EOF

${BOLD}${GREEN}With dissection and layer colors:${NC}

${CYAN}New flag: --layer-colors${NC}
  • --layer-colors: Color tree background by protocol layer depth

EOF

    run_cmd "$PROTOCOCO find ffffffffffff0040059fb1f3080045000000 --cocofile=$DEMO_DIR/slide10.coco --dissect --tree --decode --layer-colors"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Clear distinction: ${GREEN}message${NC} vs ${GREEN}layer message${NC}
  ✓ Regular messages (like ${GREEN}ethernet_header${NC}) are just data structures
  ✓ Layer messages (like ${GREEN}ethernet_frame${NC}) appear in protocol chain
  ✓ Protocol chain output: ${GREEN}[ethernet_frame:ipv4_stub]${NC}
  ✓ Visual layer depth with colored backgrounds
  ✓ Proper Wireshark dissector generation with DissectorTable chaining

EOF

}

slide11() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The IPv4 Complexity Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} IPv4 header has packed bit-level fields:

${CYAN}
 0               8              16                              32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |   DSCP/ECN    |         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
${NC}

  • ${CYAN}Version${NC}: 4 bits
  • ${CYAN}IHL${NC} (header length): 4 bits
  • Both packed into 1 byte!

${YELLOW}If only there was a way to handle bit-level packing...${NC}

EOF

}

slide12() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Bitfields${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} Nested bitfield definitions

EOF

    cat > "$DEMO_DIR/slide12.coco" << 'EOF'
version 1.0
endian be

layer message ipv4_packet {
  bits[8] version_ihl {
    bits[4] ihl
    bits[4] version
  }
  u8 dscp_ecn
  u16 total_length
  u16 identification
  bits[16] flags_fragment {
    bits[13] fragment_offset
    bit more_fragments
    bit dont_fragment
    bit reserved
  }
  u8 ttl
  u8 protocol
  u16 header_checksum
  bytes src_ip[4]
  bytes dst_ip[4]
}
EOF

    show_file "$DEMO_DIR/slide12.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Check an IPv4 header with bitfields:${NC}

EOF

    run_cmd "$PROTOCOCO check ipv4_packet 4500003c00004000400611acc0a80101c0a80102 --cocofile=$DEMO_DIR/slide12.coco --tree --layer-colors"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Bit-level field definitions
  ✓ Proper byte alignment
  ✓ Nested field access: ${GREEN}version_ihl.version${NC}
  ✓ Multi-byte bitfields supported (8, 16, 32, 64 bits)

EOF

}

slide13() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The IP Address Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} IP addresses stored as ${CYAN}c0a80172${NC} are not human-readable.

We want:
  • ${YELLOW}Storage${NC}: u32 (4 bytes)
  • ${YELLOW}Display${NC}: ${GREEN}192.168.1.114${NC}

${YELLOW}If only there was a way to format IP addresses for human-readable display...${NC}

EOF

}

slide14() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Specialized Formatters${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} IP address formatters

EOF

    cat > "$DEMO_DIR/slide14.coco" << 'EOF'
version 1.0
endian be

enum Protocol : u8 {
  ICMP = 1,
  TCP = 6,
  UDP = 17
}

layer message ipv4_packet {
  bits[8] version_ihl {
    bits[4] ihl
    bits[4] version
  }
  u8 dscp_ecn
  u16 total_length
  u16 identification
  bits[16] flags_fragment {
    bits[13] fragment_offset
    bit more_fragments
    bit dont_fragment
    bit reserved
  }
  u8 ttl
  Protocol protocol
  u16 header_checksum
  u32 src_ip [display: ipv4]
  u32 dst_ip [display: ipv4]
}
EOF

    show_file "$DEMO_DIR/slide14.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Without --decode (raw hex):${NC}

EOF

    run_cmd "$PROTOCOCO check ipv4_packet 4500003c00004000400611acc0a80101c0a80102 --cocofile=$DEMO_DIR/slide14.coco --tree --layer-colors"

    echo -e "\n${BOLD}${GREEN}With --decode (formatted IPs):${NC}\n"

    run_cmd "$PROTOCOCO check ipv4_packet 4500003c00004000400611acc0a80101c0a80102 --cocofile=$DEMO_DIR/slide14.coco --tree --decode --layer-colors"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Compact storage (4 bytes)
  ✓ Human-readable output: ${GREEN}src_ip: 192.168.1.1${NC}
  ✓ Same mechanism works for ${CYAN}ipv6${NC}, ${CYAN}mac${NC}, ${CYAN}port${NC}, ${CYAN}hex${NC}

EOF

}

slide15() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Variable Length Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} IPv4 payload size depends on total length minus header:

  • ${CYAN}total_length${NC} field tells us total packet size
  • Header is 20 bytes (when no options)
  • Payload = ${YELLOW}total_length - 20${NC}

${YELLOW}If only there was a way to compute field sizes from other fields...${NC}

EOF

}

slide16() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Size Expressions${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Solution:${NC} Arithmetic expressions in size specifiers

EOF

    cat > "$DEMO_DIR/slide16.coco" << 'EOF'
version 1.0
endian be

enum Protocol : u8 {
  TCP = 6,
  UDP = 17
}

layer message ipv4_packet {
  bits[8] version_ihl {
    bits[4] ihl
    bits[4] version
  }
  u8 dscp_ecn
  u16 total_length
  u16 identification
  bits[16] flags_fragment {
    bits[13] fragment_offset
    bit more_fragments
    bit dont_fragment
    bit reserved
  }
  u8 ttl
  Protocol protocol
  u16 header_checksum
  u32 src_ip [display: ipv4]
  u32 dst_ip [display: ipv4]

  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_stub tcp
    Protocol.UDP -> udp_stub udp
    _ -> {}
  }
}

message tcp_stub {
  u16 src_port
  u16 dst_port
}

message udp_stub {
  u16 src_port
  u16 dst_port
}
EOF

    show_file "$DEMO_DIR/slide16.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Check IPv4 packet with TCP payload:${NC}

EOF

    run_cmd "$PROTOCOCO find 450000180000400006000000c0a80101c0a80102048a1770 --cocofile=$DEMO_DIR/slide16.coco --dissect --tree --decode --layer-colors"

    cat << EOF

${BOLD}${GREEN}What we got:${NC}
  ✓ Computed field sizes
  ✓ Arithmetic expressions (${YELLOW}total_length - 20${NC})
  ✓ Field references in size expressions
  ✓ Nested pattern matching (ethertype, then protocol)

EOF

}

slide17() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Nested Polymorphism Problem${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} Now we have:

  1. Ethernet dispatching on ${CYAN}ethertype${NC}
  2. IPv4 dispatching on ${CYAN}protocol${NC}

${CYAN}
ethernet_frame
└── payload (match ethertype)
    └── ipv4_packet
        └── payload (match protocol)
            └── tcp_segment / udp_datagram / icmp_message
${NC}

${YELLOW}If only pattern matching could compose across layers...${NC}

EOF

}

slide18() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! Compositional Matching${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Answer:${NC} ${GREEN}YES!${NC} Pattern matching composes naturally.

${YELLOW}Ethernet layer:${NC}
  bytes payload[] match ethertype {
    EtherType.IPV4 -> ipv4_packet ip
  }

${YELLOW}IPv4 layer:${NC}
  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_segment tcp
  }

${BOLD}${GREEN}What we got:${NC}
  ✓ Natural composition of pattern matches
  ✓ Each layer independently defines dispatch logic
  ✓ Full chain extraction: ${GREEN}[ethernet:ip:tcp]${NC}
  ✓ Proper layer separation for maintainability

EOF

}

slide19() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The TCP Header Nightmare${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}${BOLD}Challenge:${NC} TCP is complex!

${CYAN}1. Multi-byte bitfields (16 bits packed):${NC}
   • Flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR (8 flags)
   • Reserved bits (4 bits)
   • Data offset (4 bits)

${CYAN}2. Variable-length options based on data offset:${NC}
   • Data offset tells us header size in 32-bit words
   • Options occupy: ${YELLOW}(data_offset * 4) - 20${NC} bytes
   • Each option is a different subtype!

${YELLOW}If only one specification could handle all this complexity...${NC}

EOF

}

slide20() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  TADAH! The Full TCP Specification${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Answer:${NC} ${GREEN}YES!${NC} Here's the complete TCP spec:

EOF

    cat > "$DEMO_DIR/slide20.coco" << 'EOF'
version 1.0
endian be

enum TcpOptKind : u8 {
  END = 0,
  NOP = 1,
  MSS = 2,
  WINDOW_SCALE = 3,
  TIMESTAMPS = 8
}

message tcp_option {
  TcpOptKind kind
}

message tcp_option_mss extends tcp_option {
  kind = TcpOptKind.MSS
  u8 length = 0x04
  u16 mss
}

layer message tcp_segment {
  u16 src_port [display: port]
  u16 dst_port [display: port]
  u32 seq_num
  u32 ack_num

  bits[16] data_offset_flags {
    bit fin
    bit syn
    bit rst
    bit psh
    bit ack
    bit urg
    bit ece
    bit cwr
    bits[4] reserved
    bits[4] data_offset
  }

  u16 window
  u16 checksum
  u16 urgent_ptr
  tcp_option options[data_offset_flags.data_offset * 4 - 20]
  bytes data[]
}
EOF

    show_file "$DEMO_DIR/slide20.coco"
    pause_after_file

    cat << EOF

${BOLD}${GREEN}Check TCP segment with MSS option:${NC}

EOF

    run_cmd "$PROTOCOCO check tcp_segment 048a177000000000000000006002200000000000020405b4 --cocofile=$DEMO_DIR/slide20.coco --tree --decode --layer-colors"


}

slide21() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  What We Got (TCP)${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Multi-byte bitfields:${NC}
  ✓ ${YELLOW}bits[16]${NC} for 16-bit packed fields
  ✓ Proper mask calculation in Wireshark dissectors
  ✓ Bit-level access: ${GREEN}data_offset_flags.syn${NC}

${CYAN}${BOLD}Computed option size:${NC}
  ✓ Expression: ${YELLOW}data_offset_flags.data_offset * 4 - 20${NC}
  ✓ References nested bitfield values
  ✓ Field path traversal

${CYAN}${BOLD}Polymorphic arrays:${NC}
  ✓ ${YELLOW}tcp_option options[]${NC} tries all subtypes for each element
  ✓ ${CYAN}tcp_option_mss${NC}, ${CYAN}tcp_option_nop${NC}, etc.
  ✓ Inheritance with field overrides (${YELLOW}kind = TcpOptKind.MSS${NC})

EOF

}

slide22() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  The Complete Stack${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}Let's see the full Ethernet/IP/TCP stack:${NC}

From ${YELLOW}protocols/ip.coco${NC}

EOF

    echo -e "${GREEN}${BOLD}File: protocols/ip.coco${NC}\n"
    batcat --style=plain --paging=never "$(dirname "$0")/protocols/ip.coco"
    echo ""

    cat << EOF

${BOLD}${GREEN}Protocol containment tree:${NC}

${CYAN}Command: protococo tree${NC}
  • tree: Show protocol containment hierarchy (which messages can contain which)

EOF

    run_cmd "$PROTOCOCO tree --cocofile=$(dirname "$0")/protocols/ip.coco"
}

slide23() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  What Tools Do We Get?${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

From this single ${YELLOW}.coco${NC} specification, we get:

${CYAN}${BOLD}1. Validation${NC}

EOF

    run_cmd "$PROTOCOCO check tcp_segment 048a177000000000000000006002200000000000020405b4 --cocofile=$(dirname "$0")/protocols/ip.coco --tree --layer-colors"

    echo -e "\n${CYAN}${BOLD}2. Identification${NC}\n"

    run_cmd "$PROTOCOCO find ffffffffffff0040059fb1f30800450000280000400006000000c0a80101c0a80102048a177000000000000000006002200000000000020405b4 --cocofile=$(dirname "$0")/protocols/ip.coco --dissect --tree --decode --layer-colors"

    echo -e "\n${CYAN}${BOLD}3. Wireshark Dissector Generation${NC}\n"
    echo -e "${CYAN}Command: protococo wireshark <message_name> --stack${NC}"
    echo -e "  • wireshark: Generate Wireshark Lua dissector from .coco spec"
    echo -e "  • --stack: Generate separate chained dissectors per layer (recommended)\n"

    run_cmd "$PROTOCOCO wireshark ethernet_frame --cocofile=$(dirname "$0")/protocols/ip.coco --stack | head -50"

    echo -e "\n${CYAN}${BOLD}4. Message Creation${NC}\n"
    echo -e "${CYAN}Command: protococo json-recipe <message_name>${NC}"
    echo -e "  • json-recipe: Generate JSON template for message creation\n"

    run_cmd "$PROTOCOCO json-recipe tcp_option_mss --cocofile=$(dirname "$0")/protocols/ip.coco"
}

slide24() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  Lessons Learned${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}${BOLD}What makes protocols work:${NC}
  1. ${YELLOW}Discriminators${NC} (enums) for type identification
  2. ${YELLOW}Pattern matching${NC} for polymorphic payloads
  3. ${YELLOW}Bit-level packing${NC} for efficient wire formats
  4. ${YELLOW}Computed sizes${NC} from header fields
  5. ${YELLOW}Layer composition${NC} for building stacks

${CYAN}${BOLD}What makes Protocol-as-Code work:${NC}
  1. ${YELLOW}Human-readable${NC} syntax (not XML, not ASN.1)
  2. ${YELLOW}Machine-readable${NC} for tool generation
  3. ${YELLOW}Type-safe${NC} with validation
  4. ${YELLOW}Composable${NC} patterns
  5. ${YELLOW}Single source of truth${NC} for validation, dissection, docs, generation

${BOLD}${GREEN}Result:${NC} From 200 lines of ${YELLOW}.coco${NC} to a complete toolchain
         for the foundation of the Internet.

EOF

}

slide_final() {
    clear_screen
    cat << EOF

${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}
${BOLD}  Try It Yourself${NC}
${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${NC}

${CYAN}# Install${NC}
pip install lark docopt treelib

${CYAN}# Explore the stack${NC}
protococo tree --cocofile=protocols/ip.coco

${CYAN}# Validate a frame${NC}
echo "0060089fb1f3..." | protococo find --cocofile=protocols/ip.coco --dissect --tree

${CYAN}# Generate Wireshark dissector${NC}
protococo wireshark ethernet_frame --cocofile=protocols/ip.coco --stack > ip_stack.lua


${BOLD}${YELLOW}The full Ethernet/IP/TCP stack specification is in:${NC}
  protocols/ip.coco


${BOLD}${MAGENTA}protococo: Turning protocol specifications into executable reality.${NC}

EOF

}

###########################################
# MAIN PRESENTATION FLOW
###########################################

presentation() {
    setup

    # Array of all slide functions and their display names
    local slides=(
        "slide_title:Title"
        "slide0:The Problem"
        "slide0_5:Protocol-as-Code"
        "slide1:Layer 2"
        "slide2:Enter protococo"
        "slide3:Readability"
        "slide4:Display Formatters"
        "slide5:Payload Problem"
        "slide6:Enums"
        "slide7:Polymorphism"
        "slide8:Pattern Matching"
        "slide9:Protocol Chains"
        "slide10:Layer Modifier"
        "slide11:IPv4 Complexity"
        "slide12:Bitfields"
        "slide13:IP Addresses"
        "slide14:Formatters"
        "slide15:Variable Length"
        "slide16:Size Expressions"
        "slide17:Nested Polymorphism"
        "slide18:Compositional"
        "slide19:TCP Nightmare"
        "slide20:Full TCP"
        "slide21:TCP Results"
        "slide22:Complete Stack"
        "slide23:Tools"
        "slide24:Lessons"
        "slide25:vs Wireshark"
        "slide_final:Final"
    )

    local current=0
    local total=${#slides[@]}

    while [ $current -lt $total ]; do
        # Parse slide function and name
        local slide_info="${slides[$current]}"
        local slide_func="${slide_info%%:*}"
        local slide_name="${slide_info##*:}"

        # Run current slide (it does clear_screen internally)
        $slide_func

        # Auto-scroll in tmux if enabled
        tmux_auto_scroll

        # Check if we're at the last slide
        if [ $current -eq $((total - 1)) ]; then
            # Last slide - only allow finishing
            break
        fi

        # Wait for navigation input (j/k) - no visible prompt
        next
        local direction=$?

        if [ $direction -eq 1 ]; then
            # Move forward (j was pressed)
            current=$((current + 1))
        elif [ $direction -eq 0 ] && [ $current -gt 0 ]; then
            # Move backward (k was pressed) - only if not at first slide
            current=$((current - 1))
        fi
    done

    clear_screen
    echo -e "${BOLD}${GREEN}Presentation complete!${NC}\n"
}

###########################################
# MAIN
###########################################

# Parse arguments
# Check for flags
while [[ "$1" == --* ]]; do
    case "$1" in
        --fast)
            FAST_MODE=true
            shift
            ;;
        --tmux-auto-scroll)
            TMUX_AUTO_SCROLL=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ $# -eq 0 ]; then
    # No arguments - run full presentation
    presentation
elif [ "$1" == "title" ]; then
    setup
    slide_title
elif [[ "$1" =~ ^[0-9_]+$ ]]; then
    # Numeric argument (including 0_5) - run specific slide
    setup
    slide_func="slide$1"
    if declare -f "$slide_func" > /dev/null; then
        $slide_func
    else
        echo "Error: Slide $1 does not exist"
        echo "Available slides: title, 0, 0_5, 1-25, final"
        exit 1
    fi
elif [ "$1" == "final" ]; then
    setup
    slide_final
else
    cat << EOF
${BOLD}${GREEN}═════════════════════════════════════════════════════════${NC}
${BOLD}  Protococo Presentation${NC}
${BOLD}${GREEN}═════════════════════════════════════════════════════════${NC}

Usage:
  ${CYAN}${BOLD}./demo.sh${NC}                           Run full presentation
  ${CYAN}${BOLD}./demo.sh --fast${NC}                    Run full presentation in fast mode
  ${CYAN}${BOLD}./demo.sh --tmux-auto-scroll${NC}        Run with tmux auto-scroll to top
  ${CYAN}${BOLD}./demo.sh --fast --tmux-auto-scroll${NC} Combine both modes
  ${CYAN}${BOLD}./demo.sh 0${NC}                         Run slide 0 (The Traditional Protocol Problem)
  ${CYAN}${BOLD}./demo.sh --fast 14${NC}                 Run slide 14 in fast mode
  ${CYAN}${BOLD}./demo.sh title${NC}                     Run title slide
  ${CYAN}${BOLD}./demo.sh final${NC}                     Run final slide

${YELLOW}Options:${NC}
  ${GREEN}--fast${NC}              Auto-run commands without waiting for Enter (j/k still required for slides)
  ${GREEN}--tmux-auto-scroll${NC}  Auto-enter tmux copy mode and scroll to top after each slide

${YELLOW}Controls:${NC}
  ${GREEN}j${NC} - Next slide
  ${GREEN}k${NC} - Previous slide

Available slides: title, 0, 0_5, 1-25, final
EOF
    exit 1
fi
