# Designing the Internet: A Protocol-as-Code Journey

> How we built the Ethernet/IP/TCP stack using the protococo DSL

---

## Slide 0: The Traditional Protocol Problem

**Problem**: How do we specify network protocols?

**Traditional Approach: RFCs in English**
- RFC 894: "An Ethernet frame contains..."
- RFC 791: "The version field is 4 bits..."
- Ambiguous natural language
- Not machine-readable
- Separate from implementation

**Result**: Protocol Definition ≠ Protocol Implementation
→ Implementation bugs, interoperability issues, drift over time

**Pause**: Can we do better?

---

## Enter Protocol-as-Code

**Idea**: Specify protocols in unambiguous, executable language

**Key Insight**:
The .coco file **IS** the protocol specification
(not a representation of a spec written elsewhere)

**Single Source of Truth**:
- Unambiguous syntax (no English interpretation needed)
- Machine-readable and executable
- Definition = Implementation = Documentation

Let's design the Internet stack using this approach...

---

## Protococo vs Wireshark Dissectors

**Wireshark Dissector (Lua)**: Imperative, tell computer HOW
```lua
function proto.dissector(buffer, pinfo, tree)
  local offset = 0
  tree:add(f_dst_mac, buffer(offset, 6))
  offset = offset + 6  -- Manual tracking!
  tree:add(f_src_mac, buffer(offset, 6))
end
```

**Protococo (.coco)**: Declarative, tell computer WHAT
```coco
message ethernet_header {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
}
```

**Key Differences**:
- **Wireshark** → **Protococo**
- One-way (dissect) → Bi-directional (parse + create + validate)
- Tool-specific → Universal (generates dissectors + more)
- Manual offsets → Automatic calculation

**Protococo generates dissectors, but it's much more**:
- ✓ Validate packets
- ✓ Identify messages
- ✓ Create messages
- ✓ Generate tools
- ✓ Single source of truth

---

## Slide 1: Designing Layer 2 - The Hardware Layer

**Design Challenge**: We need to send data between computers on a local network.

**Hardware Constraints**:
- Network cards only understand MAC addresses
- MAC addresses are 6 bytes long
- Each packet needs source and destination

**Pause**: Let's design this protocol. What does an Ethernet header need?

---

## Slide 2: TADAH! Enter protococo

```coco
version 1.0
endian be

message ethernet_header {
  bytes dst_mac[6]
  bytes src_mac[6]
}
```

**What we got**:
- Clear field definitions
- Fixed sizes (6 bytes each)
- Big-endian byte order by default
- Machine-readable specification

---

## Slide 3: The Readability Problem

**Challenge**: `ffffffffffff0040059fb1f3` is not human-friendly.

When debugging network issues, we need to see MAC addresses like:
- `ff:ff:ff:ff:ff:ff` (broadcast)
- `00:40:05:9f:b1:f3` (actual address)

**Pause**: How do we make hex dumps human-readable without losing precision?

---

## Slide 4: TADAH! Display Formatters

```coco
message ethernet_header {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
}
```

**What we got**:
- Raw storage stays as bytes
- Human-readable display formatting
- Debug output shows: `dst_mac: 00:60:08:9f:b1:f3`
- Validation still works on raw bytes

---

## Slide 5: The Payload Problem

**Challenge**: Ethernet can carry different types of payloads:
- IPv4 packets (0x0800)
- ARP packets (0x0806)
- VLAN tags (0x8100)
- IPv6 packets (0x86DD)

We need a way to identify what comes next!

**Pause**: How do we handle multiple payload types cleanly?

---

## Slide 6: TADAH! Enums as Discriminators

```coco
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
```

**What we got**:
- Type-safe discriminator
- Validation (only valid EtherType values accepted)
- Human-readable output: `EtherType.IPV4` instead of `2048`

---

## Slide 7: The Polymorphism Problem

**Challenge**: The payload after the EtherType field should be parsed differently based on the EtherType value:
- If `EtherType.IPV4` → parse as IPv4 packet
- If `EtherType.ARP` → parse as ARP packet
- If `EtherType.VLAN` → parse as VLAN frame
- Otherwise → just raw bytes

**Pause**: How do we dispatch on discriminator values?

---

## Slide 8: TADAH! Pattern Matching

```coco
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
```

**What we got**:
- Polymorphic payload dispatch
- Type-specific parsing for each branch
- Fallback to raw bytes
- Field names for each layer (`ip`, `arp`, `vlan`)

---

## Slide 9: The Protocol Chain Problem

**Challenge**: When debugging, we want to see the full protocol stack:
- `[ethernet:vlan:ip:tcp]`
- Not just `[tcp_segment]`

This helps understand at a glance what layers are present.

**Pause**: How do we distinguish protocol layers from regular message types?

---

## Slide 10: TADAH! Layer Modifier

```coco
layer message ethernet_frame { ... }
layer message ipv4_packet { ... }
layer message tcp_segment { ... }
message tcp_option { ... }  // NOT a layer
```

**What we got**:
- Clear distinction between protocol layers and data structures
- Protocol chain output: `[ethernet:ip:tcp]`
- `tcp_option` subtypes don't clutter the chain
- Proper Wireshark dissector generation with DissectorTable chaining

---

## Slide 11: The IPv4 Complexity Problem

**Challenge**: IPv4 header has packed bit-level fields:

```
 0               8              16                              32
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |   DSCP/ECN    |         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Version: 4 bits
- IHL (header length): 4 bits
- Both packed into 1 byte!

**Pause**: How do we handle bit-level packing?

---

## Slide 12: TADAH! Bitfields

```coco
layer message ipv4_packet {
  bits[8] version_ihl {
    bits[4] ihl
    bits[4] version
  }
  u8 dscp_ecn
  u16 total_length
  // ...
}
```

**What we got**:
- Bit-level field definitions
- Proper byte alignment
- Nested field access: `version_ihl.version`
- Multi-byte bitfields supported (8, 16, 32, 64 bits)

---

## Slide 13: The IP Address Problem

**Challenge**: IP addresses stored as `c0a80172` are not human-readable.

We want:
- Storage: `u32` (4 bytes)
- Display: `192.168.1.114`

**Pause**: Another formatting challenge?

---

## Slide 14: TADAH! Specialized Formatters

```coco
layer message ipv4_packet {
  // ... other fields
  Protocol protocol
  u16 header_checksum
  u32 src_ip [display: ipv4]
  u32 dst_ip [display: ipv4]
}
```

**What we got**:
- Compact storage (4 bytes)
- Human-readable output: `src_ip: 192.168.1.114`
- Same mechanism works for `ipv6`, `mac`, `port`, `hex`
- Wireshark dissectors automatically use correct display type

---

## Slide 15: The Variable Length Problem

**Challenge**: IPv4 payload size depends on the total packet length minus header size:
- `total_length` field tells us total packet size
- Header is 20 bytes (when no options)
- Payload = `total_length - 20`

**Pause**: How do we compute field sizes from other fields?

---

## Slide 16: TADAH! Size Expressions

```coco
layer message ipv4_packet {
  u8 dscp_ecn
  u16 total_length
  // ... other header fields (20 bytes total)

  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_segment tcp
    Protocol.UDP -> udp_datagram udp
    Protocol.ICMP -> icmp_message icmp
    _ -> {}
  }
}
```

**What we got**:
- Computed field sizes
- Arithmetic expressions (`total_length - 20`)
- Field references in size expressions
- Nested pattern matching (first by ethertype, now by ip protocol)

---

## Slide 17: The Nested Polymorphism Problem

**Challenge**: Now we have:
1. Ethernet dispatching on `ethertype`
2. IPv4 dispatching on `protocol`

We're building a protocol stack where each layer determines the next!

```
ethernet_frame
└── payload (match ethertype)
    └── ipv4_packet
        └── payload (match protocol)
            └── tcp_segment / udp_datagram / icmp_message
```

**Pause**: Does our pattern matching compose?

---

## Slide 18: TADAH! Compositional Matching

```coco
layer message ethernet_frame {
  bytes payload[] match ethertype {
    EtherType.IPV4 -> ipv4_packet ip
    // ...
  }
}

layer message ipv4_packet {
  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_segment tcp
    // ...
  }
}
```

**What we got**:
- Natural composition of pattern matches
- Each layer independently defines its dispatch logic
- Full chain extraction: `[ethernet:ip:tcp]`
- Proper layer separation for maintainability

---

## Slide 19: The TCP Header Nightmare

**Challenge**: TCP is complex:

1. **Multi-byte bitfields** (16 bits packed):
   - Flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR (8 flags)
   - Reserved bits (4 bits)
   - Data offset (4 bits)

2. **Variable-length options** based on data offset:
   - Data offset tells us header size in 32-bit words
   - Options occupy: `(data_offset * 4) - 20` bytes
   - Each option is a different subtype!

**Pause**: Can one specification handle all this?

---

## Slide 20: TADAH! The Full TCP Specification

```coco
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

// ... more option subtypes

layer message tcp_segment {
  u16 src_port [display: port]
  u16 dst_port [display: port]
  u32 seq_num
  u32 ack_num

  bits[16] data_offset_flags {
    bit fin
    bit syn
    // ... 8 flags total
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

---

## Slide 21: What We Got (TCP)

**Multi-byte bitfields**:
- `bits[16]` for 16-bit packed fields
- Proper mask calculation in Wireshark dissectors
- Bit-level access: `data_offset_flags.syn`

**Computed option size**:
- Expression: `data_offset_flags.data_offset * 4 - 20`
- References nested bitfield values
- Field path traversal

**Polymorphic arrays**:
- `tcp_option options[]` tries all subtypes for each element
- `tcp_option_mss`, `tcp_option_nop`, etc.
- Inheritance with field overrides (`kind = TcpOptKind.MSS`)

---

## Slide 22: The Complete Stack

```coco
version 1.0
endian be

enum EtherType : u16 { IPV4 = 0x0800, ARP = 0x0806, VLAN = 0x8100, IPV6 = 0x86DD }
enum Protocol : u8 { ICMP = 1, TCP = 6, UDP = 17 }
enum TcpOptKind : u8 { END = 0, NOP = 1, MSS = 2 }

layer message ethernet_frame {
  bytes dst_mac[6] [display: mac]
  bytes src_mac[6] [display: mac]
  EtherType ethertype
  bytes payload[] match ethertype {
    EtherType.IPV4 -> ipv4_packet ip
    EtherType.VLAN -> vlan_frame vlan
  }
}

layer message ipv4_packet {
  bits[8] version_ihl { bits[4] ihl bits[4] version }
  u16 total_length
  Protocol protocol
  u32 src_ip [display: ipv4]
  u32 dst_ip [display: ipv4]
  bytes payload[total_length - 20] match protocol {
    Protocol.TCP -> tcp_segment tcp
    Protocol.UDP -> udp_datagram udp
  }
}

layer message tcp_segment {
  u16 src_port [display: port]
  u16 dst_port [display: port]
  bits[16] data_offset_flags {
    bit fin
    bit syn
    bits[4] data_offset
  }
  tcp_option options[data_offset_flags.data_offset * 4 - 20]
  bytes data[]
}
```

---

## Slide 23: What Tools Do We Get?

From this single `.coco` specification:

**1. Validation**:
```bash
$ protococo check tcp_segment 048a1770... --cocofile=ip.coco --tree
tcp_segment
├── src_port: 1162
├── dst_port: 6000
├── data_offset_flags:
│   ├── fin: 1
│   ├── syn: 0
│   └── data_offset: 8
```

**2. Identification**:
```bash
$ protococo find 0060089fb1f3... --cocofile=ip.coco
[ethernet:vlan:ip:tcp]
```

**3. Wireshark Dissector**:
```bash
$ protococo wireshark ethernet_frame --cocofile=ip.coco --stack > dissector.lua
$ wireshark -X lua_script:dissector.lua capture.pcap
```

**4. Message Creation**:
```bash
$ protococo create tcp_option_mss --cocofile=ip.coco
```

---

## Slide 24: Lessons Learned

**What makes protocols work**:
1. **Discriminators** (enums) for type identification
2. **Pattern matching** for polymorphic payloads
3. **Bit-level packing** for efficient wire formats
4. **Computed sizes** from header fields
5. **Layer composition** for building stacks

**What makes Protocol-as-Code work**:
1. **Human-readable** syntax (not XML, not ASN.1)
2. **Machine-readable** for tool generation
3. **Type-safe** with validation
4. **Composable** patterns
5. **Single source of truth** for validation, dissection, documentation, and generation

**Result**: From 200 lines of `.coco` to a complete toolchain for the foundation of the Internet.

---

## Try It Yourself

```bash
# Install
pip install lark docopt treelib

# Explore the stack
protococo tree --cocofile=protocols/ip.coco

# Validate a packet
echo "0060089fb1f3..." | protococo find --cocofile=protocols/ip.coco --dissect --tree

# Generate Wireshark dissector
protococo wireshark ethernet_frame --cocofile=protocols/ip.coco --stack > ip_stack.lua
```

**The full Ethernet/IP/TCP stack specification is in `protocols/ip.coco`.**

**protococo**: Turning protocol specifications into executable reality.
