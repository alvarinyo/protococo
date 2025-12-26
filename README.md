# protococo (v0.3.0)

**A Protocol-as-Code (PAC) experiment: Aiming for executable clarity in binary protocol design.**

Protococo is a WIP project exploring the idea of expressing binary protocol specifications using an unambiguous, machine-readable DSL (`.coco`) instead of natural language documents like RFCs or IEEE standards. It seeks to bridge the gap between design and implementation, aspiring to provide a single source of truth that powers both the specification and the automated toolchain.

---

## The Vision: Protocol-as-Code

*   **Definition = Implementation**: The `.coco` file is not just a representation; it is the executable spec. The project aims to provide parsing, validation, and tool generation from a single file.
*   **Declarative over Imperative**: Move away from manually tracking offsets and bit-masks. Describe *what* the protocol looks like, and let the engine handle the *how* of the binary arithmetic.
*   **Single Source of Truth**: Aspire to prevent "spec drift" by using the same file for documentation, Wireshark dissectors, and packet validation.

---

## Quick Start

### Define a Protocol Stack (`protocols/ip.coco`)
Here is a simplified view of the Ethernet/IP/TCP stack:

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

layer message ipv4_packet {
  bits[8] version_ihl {
    bits[4] ihl
    bits[4] version
  }
  u8 dscp_ecn
  u16 total_length
  // ... other fields ...
  u32 src_ip [display: ipv4]
  u32 dst_ip [display: ipv4]

  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_segment tcp
    _ -> {}
  }
}
```

---

## DSL Reference

### File Header
Every file must declare its version and default byte order.
```python
version 1.0
endian be  # le (little-endian) or be (big-endian)
```

### Includes & Constants
```python
include "common.coco"
const STX = 0x02
const ETX = 0x03
```

### Types
| Type | Description | Size |
|------|-------------|------|
| `u8`–`u64` | Unsigned integers | 1–8 bytes |
| `i8`–`i64` | Signed integers | 1–8 bytes |
| `bytes` | Raw byte sequence | Variable |
| `string` | ASCII string | Variable |
| `string:cstr` | Null-terminated C string | Variable |
| `pad` | Padding bytes (discarded) | Variable |
| `bits[N]` | Bitfield (must be multiple of 8) | N/8 bytes |

**Endianness override:** `u16:le port` or `u32:be addr`.

### Size Specifiers
*   `[10]`: Fixed size.
*   `[length]`: Field reference.
*   `[total_length - 20]`: Arithmetic expression.
*   `[]`: Match-determined (bare `[]` requires a `match` clause).
*   `[...]`: Greedy (consumes all remaining bytes).
*   `[fill_to: 32]`: Consumes bytes until message reaches N bytes (padding).
*   `[until: 0x00]`: Consumes bytes until the specified terminator is found.

### Display Formatters
Used to transform raw bytes into semantic values in the CLI:
*   `[display: ipv4]`, `[display: ipv6]`, `[display: mac]`
*   `[display: port]`: Shows service name (e.g., `443 (https)`)
*   `[display: ascii]`: Shows hex and string (e.g., `4865 ("He")`)
*   `[display: decimal]`, `[display: binary]`, `[display: hex]`

### Pattern Matching
Polymorphic dispatch based on a discriminator field:
```python
bytes payload[] match type_id {
  0x01 -> { type_a msg } # Full body
  0x02 -> type_b msg     # Shorthand (single field)
  _    -> {}             # Default/Empty
}
```

---

## CLI Commands

### `find` (Identification)
Detect the protocol stack of a hex string.
```bash
# Detect protocol chain and show colored tree
$ protococo find <hex> --cocofile=protocols/ip.coco --dissect --format=tree --layer-colors

[ethernet:vlan:ipv4:tcp]
ethernet_frame
├── dst_mac: 00:60:08:9F:B1:F3
└── ethertype: VLAN (0x8100)
...
```

### `check` (Validation)
Strict validation against a specific message.
```bash
$ protococo check tcp_segment <hex> --decode --format=tree
```

### `wireshark` (Dissector Generation)
Generate Lua dissectors for live analysis.
```bash
$ protococo wireshark ethernet_frame --stack > my_dissector.lua
```

### `tree` (Hierarchy)
Show the containment hierarchy of all layer messages.
```bash
$ protococo tree --cocofile=protocols/ip.coco
```

---

## Common Options
*   `-L N`, `--field-bytes-limit=N`: Truncate long hex/string values to N bytes (default: 32).
*   `--decode`: Apply display formatters.
*   `--layer-colors`: Color background by protocol layer depth.
*   `--format`: Output as `compact`, `oneline`, `multiline`, `tree`, `json`, or `porcelain` (machine-readable).

---

## Installation
```bash
pip install lark docopt treelib
```

## Syntax Highlighting
Vim/Neovim and Bat (Sublime) syntax files are available in the `syntax/` directory.

---

*protococo: Aspiring to turn protocol specifications into executable reality.*
