# protococo (v0.4.0)

**A Protocol-as-Code (PAC) experiment: Making binary protocol specifications run.**

Protococo is a WIP project exploring the idea of expressing binary protocol specifications using an unambiguous, machine-readable DSL (`.coco`) instead of natural language documents like RFCs. It seeks to bridge the gap between design and implementation by providing a single source of truth that powers both the specification and the toolchain.

---

## The Vision: Protocol-as-Code

*   **Definition = Implementation**: The `.coco` file is the executable spec. The project provides parsing, validation, and tool generation from a single file.
*   **Bit-Stream Engine**: Powered by a bit-level parser, it supports bit-packed structures natively. **Note**: Byte-oriented types (integers, bytes, strings) require strict byte-alignment.
*   **Declarative over Imperative**: Move away from manually tracking offsets and bit-masks. Describe *what* the protocol looks like, and let the engine handle the *how*.
*   **Single Source of Truth**: Prevent "spec drift" by using the same file for documentation, Wireshark dissectors, and automated validation.

---

## Quick Start

### Define a Protocol Stack (`protocols/ip.coco`)
Protococo supports modular definitions using `include`:

```python
version 1.0
endian be

include "base_types.coco"

enum EtherType : u16 {
  IPV4 = 0x0800,
  ARP = 0x0806,
  VLAN = 0x8100
}

layer message ethernet_frame {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
  EtherType ethertype

  bytes payload[] match ethertype {
    EtherType.IPV4 -> ipv4_packet ip
    EtherType.ARP -> arp_packet arp
    EtherType.VLAN -> vlan_frame vlan
    _ -> {}
  }
}

// Complex pointer resolution (DNS)
message dns_name {
  bits[2] label_type
  match label_type {
    0b11 -> bits[14] pointer_offset [offset_of: dns_name]
    0b00 -> {
      bits[6] label_length
      match label_length {
        0 -> {}
        _ -> {
          bytes label_data[label_length]
          dns_name next
        }
      }
    }
  }
}
```

---

## DSL Reference

### File Header & Modularity
```python
version 1.0
endian be  # le or be
include "common.coco"
```

### Types
| Type | Description | Size | Alignment |
|------|-------------|------|-----------|
| `bits[N]` | Standalone bits | N bits | Any |
| `u8`–`u64` | Unsigned integers | 1–8 bytes | Byte-aligned |
| `i8`–`i64` | Signed integers | 1–8 bytes | Byte-aligned |
| `bytes`, `string` | Raw bytes or ASCII | Variable | Byte-aligned |
| `string:cstr` | Null-terminated C string | Variable | Byte-aligned |
| `pad` | Padding (discarded) | Variable | Byte-aligned |

### Size Specifiers
*   `[10]`: Fixed size.
*   `[length]`: Field reference.
*   `[total_length - 20]`: Arithmetic expression.
*   `[]`: Match-determined or variable-length.
*   `[...]`: Greedy (consumes all remaining data).
*   `[fill_to: 32]`: Padding until N bytes reached.
*   `[until: 0x00]`: Terminates at specified byte.

### Display Formatters
*   `[display: ipv4|ipv6|mac|port|dnsname|ascii|hex|decimal|binary]`
*   `[offset_of: Type]`: Marks a pointer to another message of `Type`.

---

## CLI Commands

### `find` (Identification)
Detect the protocol stack and show a colored tree.
```bash
$ protococo find <hex> --cocofile=protocols/ip.coco --dissect --format=tree --layer-colors
```

### `check` (Validation)
Strict validation against a specific message.
```bash
$ protococo check dns_message <hex> --decode --format=tree
```

### `wireshark` (Dissector Generation)
```bash
$ protococo wireshark ethernet_frame --stack > my_dissector.lua
```

---

## Common Options
*   `-L N`, `--field-bytes-limit=N`: Truncate long hex/string values (default: 32).
*   `--decode`: Apply display formatters.
*   `--layer-colors`: Color background by protocol layer depth.
*   `--format`: `compact`, `oneline`, `multiline`, `tree`, `json`, `porcelain`.

---

## Installation
```bash
pip install lark docopt treelib
```

*protococo: Aspiring to turn protocol specifications into executable reality.*
