# protococo

A tool for designing, testing, and debugging custom binary protocols.

## Overview

Protococo provides:
- A clean, human-readable DSL for defining binary protocol specifications (`.coco` files)
- A command-line tool for validating, identifying, and creating binary messages

## Quick Start

### Protocol Definition (.coco file)

```
version 1.0
endian le

const STX = 0x02
const ETX = 0x03

message base_message {
  u8 stx = STX                   // Start marker
  u8 msg_type                    // Message type
  u8 body_length                 // Body length
  bytes body[body_length]        // Message body
  u8 etx = ETX                   // End marker
}

message data_message extends base_message {
  msg_type = 0x01                // Data message type
  body {
    u16 data_id                  // Data identifier
    bytes payload[]              // Variable-length payload
  }
}
```

### Commands

```bash
# Validate a message against a specification
protococo check data_message "02010548656c6c6f03" --cocofile=protocol.coco

# Identify which message type matches
protococo find "02010548656c6c6f03" --cocofile=protocol.coco

# Create a message from field values
protococo create data_message --cocofile=protocol.coco

# Show message inheritance tree
protococo tree --cocofile=protocol.coco

# Display message specification
protococo mspec data_message --cocofile=protocol.coco
```

## DSL Reference

### File Header

```
version 1.0        // Required version declaration
endian le          // Default endianness: le (little) or be (big)
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
| `pad` | Padding bytes | Variable |
| `bits[8]` | Bitfield (8 bits) | 1 byte |

### Size Specifiers

```
bytes data[10]           // Fixed size: 10 bytes
bytes data[length]       // Field reference: size from 'length' field
bytes data[]             // Variable: consume remaining bytes
```

### Constants and Enums

```
const STX = 0x02
const ETX = 0x03

enum MsgType : u8 {
  TEXT = 0x01,
  BINARY = 0x02,
  CONTROL = 0x03
}
```

### Messages

```
message packet {
  u8 stx = STX              // Fixed value field
  MsgType msg_type          // Enum-typed field
  u8 length                 // Length reference field
  bytes data[length]        // Variable-length field
  u8 etx = ETX              // Fixed value field
}
```

### Inheritance

```
message child extends parent {
  msg_type = 0x01           // Override parent field value

  body {                    // Override parent field structure
    u16 id
    string name[]
  }
}
```

### Pattern Matching

```
message polymorphic {
  u8 type
  u8 length
  bytes data[length] match type {
    0x01 -> { string text[] }
    0x02 -> { u32 value }
    _ -> { bytes raw[] }
  }
}
```

### Bitfields

```
message status {
  bits[8] flags {
    bit enabled           // 1 bit
    bit ready             // 1 bit
    bits[2] mode          // 2 bits
    bits[4] reserved      // 4 bits
  }
}
```

### Arrays

```
message item {
  u8 type
  u8 data_length
  bytes data[data_length]
}

message container {
  u8 count
  item items[count]        // Array of self-delimiting messages
}
```

### Padding

```
message aligned {
  u8 type
  pad[3]                   // 3 padding bytes (discarded)
  u32 data
  pad[2] = 0xFF            // 2 padding bytes, validated as 0xFF
}
```

## Installation

```bash
pip install lark docopt treelib
```

## Usage Examples

### Validate a message

```bash
$ protococo check simple_message "aa0105 48656c6c6f 1234 bb" --cocofile=foo.coco
aa01054865 6c6c6f1234bb
```

### Find message type

```bash
$ protococo find "aa0105 48656c6c6f 1234 bb" --cocofile=foo.coco --dissect
[simple_message]    aa|01|05|48656c6c6f|1234|bb
```

### Create message from JSON

```bash
$ cat message.json
{"message_name": "simple_message", "message_fields": [
  {"field_name": "msg_type", "value": "1"},
  {"field_name": "payload", "value": "48656c6c6f"},
  {"field_name": "crc", "value": "1234"}
]}

$ protococo create --json < message.json --cocofile=foo.coco
aa010548656c6c6f1234bb
```

## Version

protococo v0.3.0
