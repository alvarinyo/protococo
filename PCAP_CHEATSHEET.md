# Protococo PCAP Analysis Cheatsheet

Quick reference for analyzing PCAP files with `pcap2hex` + `protococo`.

## Basic Command Structure

```bash
./scripts/pcap2hex.sh <pcap_file> <packet_number> | python3 protococo.py find --cocofile=protocols/internet_stack.coco [options]
```

## Common Options

- `--dissect` - Show protocol chain and hex values
- `--format=tree` - Display hierarchical tree view (requires `--dissect` to show fields)
- `--decode` - Show decoded field values instead of hex
- `--layer-colors` - Color code by protocol layer
- `--verbose` - Show all details

## Protocol Examples

### 1. Ethernet Frame
```bash
# View any packet at link layer
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect

# Tree view
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors
```

### 2. IPv4 + TCP (with Options)
```bash
# Basic view
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect

# Tree view with decoded values and layer colors
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors

# Focus on TCP options
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors | \
  grep -A 20 "options:"
```

### 3. IPv6 + ICMPv6
```bash
# Neighbor Discovery Protocol
./scripts/pcap2hex.sh tests/pcaps/ipv6_icmpv6.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect

# Tree view with layer colors
./scripts/pcap2hex.sh tests/pcaps/ipv6_icmpv6.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors
```

### 4. UDP + DNS
```bash
# DNS Query (Packet 1)
./scripts/pcap2hex.sh tests/pcaps/dns.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect

# DNS Response with multiple records (Packet 4)
# Shows MX, A records and compression pointers in dns_name
./scripts/pcap2hex.sh tests/pcaps/dns.pcap 4 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors
```

### 5. ARP
```bash
# ARP request/reply
./scripts/pcap2hex.sh tests/pcaps/arp.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect

# Detailed tree with layer colors
./scripts/pcap2hex.sh tests/pcaps/arp.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors
```

### 6. VLAN Tagged Frame
```bash
# VLAN + IPv4 + TCP
./scripts/pcap2hex.sh tests/pcaps/vlan.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect

# VLAN + ARP (packet 165)
./scripts/pcap2hex.sh tests/pcaps/vlan.pcap 165 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect --format=tree --decode --layer-colors
```

## Creating Messages from PCAP Templates

You can use a PCAP packet as a template to create a new modified message.

```bash
# 1. Generate a recipe template for a message type
python3 protococo.py json-recipe dns_message --cocofile=protocols/internet_stack.coco > dns_template.json

# 2. (Manual) Edit dns_template.json with your desired values

# 3. Create the binary message from the recipe
python3 protococo.py create --from-json=dns_template.json --cocofile=protocols/internet_stack.coco
```

## Useful Patterns

### Find All Matching Messages in PCAP
```bash
# Extract all packets and try to parse each
for i in {1..10}; do
  echo "=== Packet $i ==="
  ./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap $i 2>/dev/null | \
    python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect
done
```

### Truncate Long Field Values
```bash
# Truncate long hex/string values to 8 bytes (default is 32)
# Useful for large packets with big payloads
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect -L 8
```

### Compare Protocol Chains
```bash
# See what protocols are detected
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco --dissect | \
  head -1
```

### Extract Specific Fields
```bash
# Show only specific dissected fields
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py find --cocofile=protocols/internet_stack.coco \
    --dissect-fields=src_ip,dst_ip,src_port,dst_port --format=tree
```

### Validate Message Structure
```bash
# Check if packet matches expected message format
./scripts/pcap2hex.sh tests/pcaps/tcp_https.pcap 1 | \
  python3 protococo.py check ethernet_no_fcs --cocofile=protocols/internet_stack.coco
```

## Protocol Messages Available in internet_stack.coco

**Link Layer:**
- `ethernet_frame` - Standard Ethernet II frame
- `vlan_frame` - 802.1Q VLAN tagged frame
- `ethernet_header` - Ethernet header only

**Network Layer:**
- `ipv4_packet` - IPv4 packet with header
- `ipv6_packet` - IPv6 packet with header  
- `arp_packet` - ARP request/reply
- `icmp_message` - ICMPv4 messages

**Transport Layer:**
- `tcp_segment` - TCP segment with options
- `tcp_option` - Individual TCP option (NOP, MSS, timestamps, etc.)
- `udp_datagram` - UDP datagram

**Application Layer:**
- `dns_message` - DNS query/response
- `dns_question` - DNS question section
- `dns_rr` - DNS resource record (base)
- `dns_rr_a` - IPv4 address record
- `dns_rr_aaaa` - IPv6 address record
- `dns_rr_cname` - Canonical name record
- `dns_rr_mx` - Mail exchange record
- `dns_rr_ptr` - Pointer record
- `dns_rr_txt` - Text record

## Tips

1. **Start with `--dissect`** to see protocol chain and hex layout
2. **Use `--dissect --format=tree --decode`** for detailed hierarchical view
3. **Pipe to `grep`** to focus on specific fields
4. **Check packet count** with `tshark -r <pcap> | wc -l` before extracting
5. **Use `--layer-colors`** for visual protocol layer separation
