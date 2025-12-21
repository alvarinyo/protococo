# protococo

**Design, validate, and debug binary protocols with clarity.**

Protococo brings the simplicity of modern IDLs to binary protocol engineering. Define network protocols, device communication formats, or custom binary structures in a clean, human-readable syntax—then validate packets, identify message types, generate Wireshark dissectors, and more.

Born from real-world protocol debugging needs, protococo turns hours of hex dump archaeology into seconds of structured analysis.

## What Makes It Different

- **Declarative DSL**: Define protocols like you document them—with inheritance, pattern matching, and semantic field names
- **Protocol-aware**: Built-in understanding of layers, discriminators, and polymorphic structures
- **Instant validation**: Check if bytes match your spec, see exactly what doesn't comply
- **Smart identification**: Feed it unknown bytes, get back the most likely message type
- **Wireshark integration**: Generate Lua dissectors with proper layer chaining from your `.coco` files
- **Field-level formatting**: See IP addresses as IPs, MAC addresses as MACs, not raw hex

## Quick Start

### Define a Protocol Stack

Here's part of an Ethernet/IP/TCP stack in `.coco` format:

```
version 1.0
endian be

enum EtherType : u16 {
  IPV4 = 0x0800,
  ARP = 0x0806,
  VLAN = 0x8100
}

enum Protocol : u8 {
  TCP = 6,
  UDP = 17,
  ICMP = 1
}

// Ethernet frame - root protocol layer
layer message ethernet_frame {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
  EtherType ethertype

  // Polymorphic payload based on ethertype
  bytes payload[] match ethertype {
    EtherType.IPV4 -> ipv4_packet ip
    EtherType.ARP -> arp_packet arp
    EtherType.VLAN -> vlan_frame vlan
    _ -> {}
  }
}

// IPv4 with nested protocol detection
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

  // Size computed from header, payload dispatched by protocol
  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_segment tcp
    Protocol.UDP -> udp_datagram udp
    Protocol.ICMP -> icmp_message icmp
    _ -> {}
  }
}

// TCP with polymorphic options array
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
```

### Commands

```bash
# Identify protocol from packet capture
$ protococo find 0060089fb1f30040...  --cocofile=protocols/ip.coco
[ethernet:vlan:ip:tcp]  # Shows full protocol chain

# Validate against specific message type
$ protococo check tcp_segment 048a1770...  --cocofile=protocols/ip.coco --tree
tcp_segment
├── src_port: 1162
├── dst_port: 6000
├── seq_num: 1309986985
├── ack_num: 1295865017
├── data_offset_flags:
│   ├── fin: 1
│   ├── syn: 0
│   ├── ack: 1
│   └── data_offset: 8
└── window: 28920

# Identify message with field dissection
$ protococo find 0060089fb1f30040...  --cocofile=protocols/ip.coco \
    --dissect --decode --tree

# Filter specific fields
$ protococo find <hex>  --cocofile=protocols/ip.coco \
    --dissect-fields="src_ip,dst_ip,src_port,dst_port"

# Show protocol containment hierarchy
$ protococo tree --cocofile=protocols/ip.coco
ethernet_frame
├── vlan_frame
│   ├── ipv4_packet
│   │   ├── tcp_segment
│   │   ├── udp_datagram
│   │   └── icmp_message
│   └── arp_packet
└── ipv6_packet
    └── tcp_segment

# Generate Wireshark dissector (chained layers)
$ protococo wireshark ethernet_frame --cocofile=protocols/ip.coco --stack > dissector.lua
```

## DSL Reference

### File Header

```
version 1.0        # Required version declaration
endian be          # Default endianness: be (big) or le (little)
```

### Types

| Type | Description | Size |
|------|-------------|------|
| `u8`, `i8` | Unsigned/signed 8-bit integer | 1 byte |
| `u16`, `i16` | Unsigned/signed 16-bit integer | 2 bytes |
| `u32`, `i32` | Unsigned/signed 32-bit integer | 4 bytes |
| `u64`, `i64` | Unsigned/signed 64-bit integer | 8 bytes |
| `bytes` | Raw byte sequence | Variable |
| `string` | ASCII string | Variable |
| `string:cstr` | Null-terminated C string | Variable |
| `pad` | Padding bytes (discarded) | Variable |
| `bits[N]` | Bitfield (8, 16, 32, or 64 bits) | N/8 bytes |

**Endianness override:**
```
u16:le port        # Little-endian 16-bit integer
u32:be addr        # Big-endian 32-bit integer (overrides file default)
```

### Size Specifiers

```
bytes data[10]                    # Fixed size: 10 bytes
bytes data[length]                # Field reference
bytes data[total_length - 20]     # Computed size with arithmetic
bytes data[]                      # Variable: consume remaining
```

### Display Formatters

```
u32 addr [display: ipv4]          # Show as 192.168.1.1
bytes mac[6] [display: mac]       # Show as aa:bb:cc:dd:ee:ff
u16 port [display: port]          # Show as port number
u8 flags [display: hex]           # Show as 0xFF
bytes ip6[16] [display: ipv6]     # Show as IPv6 address
```

### Enums

```
enum Protocol : u8 {
  ICMP = 1,
  TCP = 6,
  UDP = 17
}

// Use in fields
Protocol protocol          # Validates against enum values
```

### Layer Messages

Mark protocol layers with `layer` for proper dissector generation and protocol chain display:

```
layer message ethernet_frame { ... }
layer message ipv4_packet { ... }
layer message tcp_segment { ... }
```

Regular messages (non-layers):
```
message tcp_option { ... }         # Base for polymorphic options
message ethernet_header { ... }    # Embedded in ethernet_frame
```

### Inheritance

```
message tcp_option {
  TcpOptKind kind
}

message tcp_option_mss extends tcp_option {
  kind = TcpOptKind.MSS      # Override with fixed value
  u8 length = 0x04
  u16 mss
}
```

### Pattern Matching

Dispatch on discriminator fields to parse polymorphic structures:

```
layer message ipv4_packet {
  ipv4_header header
  bytes payload[header.total_length - 20] match header.protocol {
    Protocol.TCP -> tcp_segment tcp
    Protocol.UDP -> udp_datagram udp
    Protocol.ICMP -> icmp_message icmp
    _ -> {}                        # Default: raw bytes
  }
}
```

### Bitfields

Pack multiple values into fixed-width bit sequences:

```
bits[16] data_offset_flags {
  bit fin                # 1 bit
  bit syn                # 1 bit
  bit rst                # 1 bit
  bits[4] reserved       # 4 bits
  bits[4] data_offset    # 4 bits
}
```

Supports 8, 16, 32, and 64-bit bitfields.

### Polymorphic Arrays

Arrays that try all subtypes for each element:

```
message tcp_option { TcpOptKind kind }
message tcp_option_mss extends tcp_option { ... }
message tcp_option_nop extends tcp_option { ... }

message tcp_segment {
  tcp_option options[20]    # Each element tries all tcp_option subtypes
}
```

### Structure Overrides

Override embedded message structure inline:

```
message base {
  u8 type
  bytes data[10]
}

message child extends base {
  type = 0x01
  data {                    # Override data field structure
    u16 id
    bytes payload[8]
  }
}
```

## Commands

### check

Validate a hex message against a specific message type:

```bash
protococo check <message_name> <hex_string> [options]

Options:
  --format=<fmt>        Output format: compact, oneline, multiline, tree, porcelain, json
  --tree                Display as tree structure with box-drawing characters
  --decode              Apply display formatters (IP addresses, MAC, etc.)
  --layer-colors        Color tree background by protocol layer depth
  --field-bytes-limit=N Truncate field values to N bytes (default: 8, 0=unlimited)
  --verbose             Show field validation errors
```

Examples:
```bash
# Compact output
protococo check tcp_segment 048a1770... --cocofile=protocols/ip.coco

# Tree with decoded values and layer colors
protococo check ethernet_frame 0060089fb1f3... --cocofile=protocols/ip.coco \
    --tree --decode --layer-colors

# Machine-readable porcelain format
protococo check ipv4_packet 4500... --cocofile=protocols/ip.coco \
    --format=porcelain --decode
```

### find

Identify which message type(s) match a hex string:

```bash
protococo find [<hex_string>...] [options]

Options:
  --dissect                     Show field dissection
  --dissect-fields=<fields>     Show only specific fields (comma-separated)
  --list                        Show all matching messages ranked by fitness
  --decode                      Apply display formatters
  --tree                        Display as tree structure
  --format=<fmt>                Output format
  --field-bytes-limit=N         Truncate field values
```

Examples:
```bash
# Find best match (shows protocol chain)
protococo find 0060089fb1f3004005... --cocofile=protocols/ip.coco
[ethernet:vlan:ip:tcp]

# With field dissection
protococo find 0060089fb1f3... --cocofile=protocols/ip.coco --dissect --decode

# Filter specific fields
protococo find 0060089fb1f3... --cocofile=protocols/ip.coco \
    --dissect-fields="src_ip,dst_ip,protocol"

# From stdin (space or newline separated)
echo "0060089fb1f3... aa01bb02cc..." | protococo find --cocofile=protocols/ip.coco

# Show all candidates ranked
protococo find 0060089fb1f3... --cocofile=protocols/ip.coco --list
```

### create

Create a message from field values:

```bash
protococo create <message_name> [options]
protococo create --from-json=<file> [options]

# Interactive mode (prompts for field values)
protococo create tcp_option_mss --cocofile=protocols/ip.coco

# From JSON file
protococo create --from-json=message.json --cocofile=protocols/ip.coco
```

### json-recipe

Generate JSON template for message creation:

```bash
protococo json-recipe <message_name>... --cocofile=<file>

# Example
protococo json-recipe tcp_option_mss tcp_option_nop --cocofile=protocols/ip.coco
[
  {
    "message_name": "tcp_option_mss",
    "message_fields": [
      {"field_name": "mss", "value": "", "value_is_file_path": false, "should_encode": false}
    ]
  }
]
```

### tree

Show protocol containment hierarchy:

```bash
protococo tree --cocofile=protocols/ip.coco
ethernet_frame
├── vlan_frame
│   ├── ipv4_packet
│   │   ├── tcp_segment
│   │   ├── udp_datagram
│   │   └── icmp_message
│   └── arp_packet
└── ipv6_packet
```

### mspec

Display message specification:

```bash
protococo mspec tcp_segment --cocofile=protocols/ip.coco
message tcp_segment {
  u16 src_port
  u16 dst_port
  u32 seq_num
  u32 ack_num
  bits[16] data_offset_flags
  ...
}
```

### wireshark

Generate Wireshark Lua dissector:

```bash
protococo wireshark [<message_name>] --cocofile=<file> [--stack]

# Monolithic dissector (inline layer parsing)
protococo wireshark ethernet_frame --cocofile=protocols/ip.coco > dissector.lua

# Stack mode (separate chained dissectors - recommended)
protococo wireshark ethernet_frame --cocofile=protocols/ip.coco --stack > dissector.lua

# Install and use
cp dissector.lua ~/.local/lib/wireshark/plugins/
wireshark -X lua_script:dissector.lua capture.pcap
```

Stack mode generates proper DissectorTable chaining following Wireshark best practices.

## Installation

```bash
pip install lark docopt treelib
```

## Output Formats

### compact (default)
```
aa01054865 6c6c6f1234bb
```

### oneline
```
|stx: aa|type: 01|len: 05|body: 48656c6c6f|crc: 1234|etx: bb|
```

### tree
```
tcp_segment
├── src_port: 1162
├── dst_port: 6000
├── seq_num: 1309986985
└── data_offset_flags:
    ├── fin: 1
    ├── syn: 0
    └── ack: 1
```

### porcelain (machine-readable)
```
OK   src_port   048a      1162
OK   dst_port   1770      6000
OK   seq_num    4e1bc929  1309986985
```

### json
```json
{
  "is_valid": true,
  "message_name": "tcp_segment",
  "fields": [
    {"name": "src_port", "value": 1162, "hex": "048a"},
    {"name": "dst_port", "value": 6000, "hex": "1770"}
  ]
}
```

## Real-World Example

Debugging a VLAN-tagged TCP packet:

```bash
# Capture hex from tshark
$ tshark -r capture.pcap -x | grep "^0000" | cut -d' ' -f2- | tr -d ' \n'
0060089fb1f3004005...

# Identify protocol chain
$ protococo find 0060089fb1f3... --cocofile=protocols/ip.coco --dissect --decode --tree
[ethernet:vlan:ip:tcp]

ethernet_frame
├── dst_mac: 00:60:08:9f:b1:f3
├── src_mac: 00:40:05:40:ef:24
└── ethertype: VLAN (33024)

vlan_frame
├── vlan_id: 2
├── pcp: 0
└── inner_ethertype: IPV4 (2048)

ipv4_packet
├── version: 4
├── ihl: 5
├── total_length: 1500
├── protocol: TCP (6)
├── src_ip: 131.151.32.129
└── dst_ip: 131.151.32.21

tcp_segment
├── src_port: 1162
├── dst_port: 6000
├── seq_num: 1309986985
├── syn: 0
├── ack: 1
└── window: 28920

# Generate Wireshark dissector for live analysis
$ protococo wireshark ethernet_frame --cocofile=protocols/ip.coco --stack > ip_stack.lua
$ wireshark -X lua_script:ip_stack.lua capture.pcap
```

## License

See LICENSE file for details.

## Version

protococo v0.3.0
