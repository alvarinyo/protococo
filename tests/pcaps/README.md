# Protocol Sample Captures

This directory contains sample PCAP files for testing protococo against real network traffic.

## Available PCAPs

| File | Protocol | Source | Description |
|------|----------|--------|-------------|
| `arp.pcap` | ARP | Wireshark Samples | ARP request/reply traffic |
| `dns.pcap` | DNS | Wireshark Samples | DNS queries and responses |
| `udp.pcap` | UDP | Wireshark Samples | UDP traffic |
| `tcp_https.pcap` | TCP/TLS | Local | HTTPS traffic over TCP |
| `vlan.pcap` | VLAN/TCP | Local | VLAN-tagged Ethernet frames |
| `ipv6_icmpv6.pcap` | IPv6/ICMPv6 | Local | IPv6 with ICMPv6 traffic |

## Usage Examples

### Extract and Parse with protococo

```bash
# Parse DNS traffic
./scripts/pcap2hex.sh tests/pcaps/dns.pcap | python3 protococo.py find --cocofile=protocols/ip.coco --dissect --decode

# Parse ARP traffic (specify ethernet_frame for layer protocols)
./scripts/pcap2hex.sh tests/pcaps/arp.pcap | head -1 | python3 protococo.py check ethernet_frame --cocofile=protocols/ip.coco --tree --decode

# Parse VLAN-tagged traffic
./scripts/pcap2hex.sh tests/pcaps/vlan.pcap | head -1 | python3 protococo.py find --cocofile=protocols/ip.coco

# Parse IPv6 + ICMPv6
./scripts/pcap2hex.sh tests/pcaps/ipv6_icmpv6.pcap | head -1 | python3 protococo.py find --cocofile=protocols/ip.coco --dissect --tree

# Extract specific packet number
./scripts/pcap2hex.sh tests/pcaps/dns.pcap 3 | python3 protococo.py find --cocofile=protocols/ip.coco

# Extract multiple packets (one per line)
./scripts/pcap2hex.sh tests/pcaps/dns.pcap 1 5 | python3 protococo.py find --cocofile=protocols/ip.coco
```

### Inspect with tshark

```bash
# Show packet summary
tshark -r tests/pcaps/dns.pcap -c 5

# Show full packet details
tshark -r tests/pcaps/dns.pcap -c 1 -V

# Filter by protocol
tshark -r tests/pcaps/dns.pcap -Y "dns" -c 5

# Show specific fields
tshark -r tests/pcaps/dns.pcap -T fields -e ip.src -e ip.dst -e dns.qry.name
```

## Protocol-Specific Examples

### DNS (Port 53 UDP)

```bash
# Show DNS query/response with decoded values
./scripts/pcap2hex.sh tests/pcaps/dns.pcap | head -1 | \
  python3 protococo.py find --cocofile=protocols/ip.coco --dissect --decode --tree
```

Expected output shows: `[ethernet:ip:udp]` with UDP port 53

### ARP

```bash
# Parse ARP request showing MAC and IP addresses
./scripts/pcap2hex.sh tests/pcaps/arp.pcap | head -1 | \
  python3 protococo.py check ethernet_frame --cocofile=protocols/ip.coco --tree --decode
```

Shows ARP request with:
- Sender MAC/IP
- Target MAC/IP (00:00:00:00:00:00 for requests)
- Operation (REQUEST/REPLY)

### VLAN (802.1Q)

```bash
# Parse VLAN-tagged frame
./scripts/pcap2hex.sh tests/pcaps/vlan.pcap | head -1 | \
  python3 protococo.py find --cocofile=protocols/ip.coco --dissect --tree
```

Shows: `[ethernet:vlan:ip:tcp]` with VLAN ID, PCP, and DEI fields

### IPv6 + ICMPv6

```bash
# Parse IPv6 with ICMPv6
./scripts/pcap2hex.sh tests/pcaps/ipv6_icmpv6.pcap | head -1 | \
  python3 protococo.py find --cocofile=protocols/ip.coco --dissect --tree --decode
```

Shows: `[ethernet:ip6:icmpv6]` with IPv6 addresses and ICMPv6 message

## Notes

- Use `--tree` for hierarchical output
- Use `--decode` to format IPs, MACs, and ports
- Use `--layer-colors` for colored tree output by protocol layer
- For layer protocols (ethernet_frame, ipv4_packet, etc.), use `check` with explicit message name
- The `find` command identifies the best-matching protocol automatically
- Some PCAPs may have trailing data or options that cause validation warnings

## Adding New PCAPs

To add more sample captures:

```bash
# Download from Wireshark GitLab
curl -sL "https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/<filename>" \
  -o tests/pcaps/<name>.pcap

# Verify it's a valid pcap
file tests/pcaps/<name>.pcap
tshark -r tests/pcaps/<name>.pcap -c 1

# Test with protococo
./scripts/pcap2hex.sh tests/pcaps/<name>.pcap | head -1 | \
  python3 protococo.py find --cocofile=protocols/ip.coco
```

Update this README with the new file information.
