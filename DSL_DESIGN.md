# Protocol DSL Design Document

Version: 0.3.0 (Draft)

**Changes from 0.2.0:**
- Removed `lengthof` keyword - use explicit size references with auto-calculation
- Removed `u8[N]` primitive array syntax - use `bytes[N]` instead
- Added variable-length field rules (only one, at end)
- Added array element rules (must be self-delimiting)
- Clarified override compatibility rules
- Specified constant types (integers and strings)
- Removed `if` from reserved keywords
- Simplified match syntax: `field match discriminator { ... }` (field declared once)

---

## 1. File Structure

Every file must start with a header:

```
version 1.0
endian le        // REQUIRED: 'le' or 'be' - default endianness

// Optional imports (future)
// import "common.coco"

// Constants
const STX = 0x02
const ETX = 0x03
const MIME_ASOS = "asos"

// Enums
enum CommandType : u8 {
  CMD1 = 0x01,
  CMD2 = 0x02
}

// Messages
message packet { ... }
```

**Header requirements:**
- `version 1.0` - DSL version
- `endian le|be` - MANDATORY byte order for multi-byte types

---

## 2. Basic Syntax

```
message message_name {
  type field_name = value  // Fixed value
  type field_name          // Variable value (auto-calculated if referenced)
}

// Comments
// Single line

/* Multi-line
   comment */
```

---

## 3. Type System

### Fixed-Size Integers

```
u8              // unsigned 8-bit
u16             // unsigned 16-bit, uses file default endianness
u16:le          // explicit little-endian
u16:be          // big-endian
u32, u32:le, u32:be
u64, u64:le, u64:be

i8, i16, i32, i64  // signed (same endianness rules)
```

### Variable-Length Types

```
bytes[N]        // N bytes (N = literal or field reference)
bytes[]         // Variable length to end of message/field

string[N]       // ASCII string, N bytes
string:cstr[]   // C-style null-terminated string (ASCII)
string[]        // ASCII to end of message/field
```

**String rules:**
- All strings are ASCII in v1
- `string:cstr[]` reads until first 0x00 byte (null terminator consumed but not included in value)
- `string[]` reads all remaining bytes (no null terminator expected)

### Bit Fields (Single Byte Only)

```
bits[8] field_name {
  bit     flag1        // bit 0 (LSB)
  bits[3] mode         // bits 1-3
  bits[4] reserved     // bits 4-7 (MSB)
}
```

**Bit field rules:**
- **Only 8-bit bit fields allowed** (single byte)
- Bits numbered from LSB (bit 0) to MSB (bit 7)
- Sum of all bits must equal 8
- For multi-byte bit operations, use multiple `bits[8]` fields
- Individual bit field values are treated as unsigned integers

---

## 4. Constants and Enums

### Constants

```
const STX = 0x02           // Integer constant
const MAX_SIZE = 256       // Integer constant
const MIME_TYPE = "asos"   // String constant
```

**Constant types:**
- Integer literals: `0x02`, `256`, `0b1010`
- String literals: `"hello"`, `"asos"`

### Enums

```
enum CommandType : u8 {
  CLOSE   = 0x00,
  OPEN    = 0x01,
  TXDATA  = 0x02,
  ANNOUNCE = 0x03
}

// Usage
message example {
  u8 stx = STX
  CommandType cmd
  u8 etx = ETX
}
```

**Enum validation (strict):**
- During parsing, if value doesn't match any enum member → **parse error**
- Future: may add lenient mode for forward compatibility

---

## 5. Length Relationships

Use **explicit size references** with auto-calculation:

```
message example {
  u8 length              // Auto-calculated during encoding
  bytes data[length]     // Size determined by 'length' field
}
```

**How it works:**

**During encoding (create):**
1. User provides `data`
2. Parser sees `data[length]` references `length` field
3. Auto-calculate: `length = size of data`
4. Encode message

**During decoding (parse):**
1. Read `length` field value (e.g., 10)
2. Read 10 bytes into `data`

**Examples:**
```
message simple {
  u8 length
  bytes data[length]
}

message with_string {
  u8 text_length
  string text[text_length]
}

message nested {
  u16 body_length
  bytes body[body_length] {
    u8 inner_length
    bytes inner[inner_length]
  }
}
```

**Auto-calculation rules:**
- If field `X` is referenced in a size expression `[X]`, and `X` has no explicit value, it's auto-calculated
- Auto-calculated fields must be integer types (u8, u16, u32, u64, i8, i16, i32, i64)
- Size expressions support arithmetic: `[length]`, `[length - 2]`, `[header_len + payload_len]`, `[count * 4]`

---

## 6. Variable-Length Field Rules

**Rule 1:** At most ONE variable-length field without explicit size per message/structure.

**Rule 2:** That field must be at the END.

```
// VALID - unbounded field at end
message valid {
  u8 type
  bytes data[]
}

// INVALID - two unbounded fields
message invalid1 {
  bytes a[]
  bytes b[]
}

// INVALID - unbounded field not at end
message invalid2 {
  bytes data[]
  u8 type
}

// VALID - all fields have sizes except last
message valid2 {
  u8 a_length
  bytes a[a_length]
  u8 b_length
  bytes b[b_length]
  bytes remainder[]   // OK - at end
}
```

---

## 7. Inheritance

**Override only - no field addition.**

### Simple Value Override

```
message base {
  u8 stx = 0x02
  u8 msg_type
  bytes payload[]
  u8 etx = 0x03
}

message derived extends base {
  msg_type = 0x23  // Override: specific value
  // Cannot add new fields!
}

// Result: stx=0x02, msg_type=0x23, payload[], etx=0x03
```

### Structure Override

Replace `bytes[]` or `bytes[N]` field with structure:

```
message base {
  u8 stx = 0x02
  u8 body_length
  bytes body[body_length]
  u8 etx = 0x03
}

message derived extends base {
  body {                    // Override 'body' with structure
    u8 field_a
    u16 field_b
    bytes data[]
  }
  // body_length auto-calculated from expanded body
}
```

### Nested Override

```
message level1 {
  u8 outer_length
  bytes outer[outer_length]
}

message level2 extends level1 {
  outer {
    u8 inner_length
    bytes inner[inner_length]
  }
}

message level3 extends level2 {
  outer.inner {              // Dot notation for nested
    string mime_type[10]
    bytes content[]
  }
}
```

### Override Compatibility Rules

| From | To | Valid? |
|------|-----|--------|
| `bytes[]` | structure | ✅ Yes |
| `bytes[N]` | structure | ✅ Yes |
| `bytes[]` | `bytes[N]` | ❌ No (changes semantics) |
| `u8` (no value) | `u8 = 0x01` | ✅ Yes (set value) |
| `u8 = 0x01` | `u8 = 0x02` | ✅ Yes (change value) |
| `u8` | `u16` | ❌ No (type change) |
| `u8` | `EnumType` (u8-based) | ✅ Yes (if enum underlying type matches) |
| `string[]` | `string[N]` | ❌ No (changes semantics) |

**Nested override rules:**
- Can only override fields that exist in parent
- Path must be valid: `outer.inner` requires `outer` to have `inner` field
- Cannot add new nested fields, only override existing ones

### Inheritance Validation Errors

- Trying to add fields to child message
- Overriding field that doesn't exist in parent
- Overriding field with incompatible type
- Invalid nested path (e.g., `outer.nonexistent`)

---

## 8. Pattern Matching

For fields with structure depending on another field's value:

```
message packet {
  u8 msg_type
  u8 payload_length

  bytes payload[payload_length] match msg_type {
    0x01 -> { string text[] }
    0x02 -> { bytes data[] }
    _ -> { bytes unknown[] }
  }
}
```

**Syntax:** `<field_declaration> match <discriminator> { <branches> }`

The field declaration comes first, then `match` specifies which field determines the internal structure.

**Match rules:**
- Must be **exhaustive**: cover all possible values OR have `_` default case
- Each branch defines the internal structure of the field

**Enum matching:**
```
enum MsgType : u8 {
  TEXT = 0x01,
  DATA = 0x02
}

message typed {
  MsgType msg_type
  u8 payload_length

  bytes payload[payload_length] match msg_type {
    MsgType.TEXT -> { string text[] }
    MsgType.DATA -> { bytes data[] }
    // Exhaustive: all enum values covered, no default needed
  }
}
```

**Match semantics:**
- During encoding: use branch matching the discriminator's value
- During decoding: read discriminator, then parse field according to matching branch
- If no match and no default: **parse error**

---

## 9. Arrays of Structures

```
message item {
  u16 id
  u8 data_length
  bytes data[data_length]
}

message container {
  u8 item_count
  item items[item_count]
}
```

**Array size:**
- Literal: `item items[5]`
- Field reference: `item items[count]`
- Variable to end: `item items[]` (only at end of message)

### Array Element Rules

**Rule:** Array elements must be **self-delimiting** (fixed size or have internal length fields).

```
// VALID - self-delimiting (has length field)
message entry {
  u8 text_length
  string text[text_length]
}

message log {
  u8 entry_count
  entry entries[entry_count]   // OK
}

// INVALID - not self-delimiting
message bad_entry {
  string text[]   // Unbounded - can't determine where entry ends
}

message bad_log {
  u8 entry_count
  bad_entry entries[entry_count]   // ERROR
}

// VALID - fixed size
message fixed_entry {
  u8 type
  bytes data[10]   // Fixed 10 bytes
}

message fixed_log {
  u8 entry_count
  fixed_entry entries[entry_count]   // OK - each entry is 11 bytes
}
```

**TLV Pattern (recommended for extensibility):**
```
message tlv_field {
  u8 field_type [display: hex]
  u8 field_length
  bytes value[field_length]
}

message extensible_packet {
  u8 stx = STX
  u8 field_count
  tlv_field fields[field_count]
  u8 etx = ETX
}
```

---

## 10. Padding and Alignment

```
message aligned {
  u8 field1
  pad[3]           // 3 bytes of padding (default 0x00)
  u32 field2
}

message custom_padding {
  u8 type
  pad[3] = 0xFF    // Padding with specific value
  u32 data
}
```

**Padding semantics:**

**During encoding:**
- `pad[N]` writes N bytes with specified value (default 0x00)

**During decoding:**
- `pad[N]` reads and **discards** N bytes (no validation)
- `pad[N] = 0xFF` reads N bytes, **validates** all are 0xFF, then discards
  - If validation fails → **parse error**

---

## 11. Field Attributes (Metadata)

Optional metadata for documentation and tooling:

```
message example {
  u8 type [display: hex, doc: "Message type indicator"]
  string name[32] [display: string, doc: "Device name"]
  u32 timestamp [display: decimal, doc: "Unix timestamp"]
  bytes payload[] [doc: "Message payload"]
}
```

**Supported attributes:**
- `display: hex|decimal|string|binary` - Display format hint for tools
- `doc: "text"` - Human-readable documentation

---

## 12. Error Handling and Validation

**Parse errors (strict validation):**

1. **Length mismatch:** Not enough bytes for field
2. **Enum out of range:** Enum value not defined in enum members
3. **Match no match:** No matching branch (and no default `_`)
4. **Bit field sum:** Bit fields don't sum to 8 bits
5. **Padding validation:** `pad[N] = 0xFF` finds non-0xFF bytes
6. **Inheritance violation:** Override non-existent field, add new fields, etc.
7. **Invalid nested path:** Reference to non-existent nested field
8. **Non-self-delimiting array element:** Array element type has unbounded fields
9. **Multiple unbounded fields:** More than one `[]` field without size
10. **Unbounded field not at end:** `[]` field followed by other fields

---

## 13. Reserved Keywords

Cannot be used as message names, field names, or identifiers:

```
version, endian, const, enum, message, extends, match,
bits, bit, pad, u8, u16, u32, u64, i8, i16, i32, i64,
bytes, string, le, be, cstr, display, doc
```

---

## 14. Complete Example

Full example translating bti.coco ASOS protocol:

```
version 1.0
endian le

const STX = 0x02
const ETX = 0x03
const MIME_ASOS = "asos"

enum AsosCommand : u8 {
  CLOSE    = 0x00,
  OPEN     = 0x01,
  TXDATA   = 0x02,
  ANNOUNCE = 0x03
}

// Base binary packet
message binary_data_packet {
  u8 stx = STX
  u8 packet_type = 0x23
  u8 body_length
  bytes body[body_length]
  u16 checksum [doc: "CRC-16 checksum (not validated in v1)"]
  u8 etx = ETX
}

// MIME wrapper layer
message mime_packet extends binary_data_packet {
  body {
    u8 sequence_number = 0x00
    u8 mime_type_length
    string mime_type[mime_type_length]
    u32 content_length
    bytes content[content_length]
  }
}

// ASOS protocol over MIME
message asos_message extends mime_packet {
  body.mime_type = MIME_ASOS

  body.content {
    AsosCommand asos_cmd
    u8 sequence
    bytes data[]
  }
}

// Specific ASOS commands
message asos_txdata extends asos_message {
  body.content.asos_cmd = AsosCommand.TXDATA
}

message asos_open extends asos_message {
  body.content.asos_cmd = AsosCommand.OPEN
  body.content.data {
    string:cstr filename[]
  }
}

message asos_close extends asos_message {
  body.content.asos_cmd = AsosCommand.CLOSE
}

message asos_announce extends asos_message {
  body.content.asos_cmd = AsosCommand.ANNOUNCE
  body.content.data {
    string info[]
  }
}

// Example with pattern matching
message protocol_wrapper {
  u8 stx = STX
  u8 protocol_type [display: hex, doc: "Protocol discriminator"]
  u16 payload_length

  bytes payload[payload_length] match protocol_type {
    0x01 -> { asos_message msg }
    0x02 -> { binary_data_packet msg }
    _ -> { bytes raw_data[] }
  }

  u8 etx = ETX
}

// TLV pattern for extensible data
message tlv_entry {
  u8 tag_type [display: hex]
  u8 tag_length
  bytes tag_value[tag_length]
}

message extensible_message {
  u8 stx = STX
  u8 tag_count
  tlv_entry tags[tag_count]
  u8 etx = ETX
}
```

---

## 15. Implementation Notes

**Parser:** Python + Lark (PEG grammar)

**AST:** Python dataclasses representing:
- FileHeader (version, endianness)
- Constants (integer and string)
- Enums
- Messages (with inheritance chain)
- Fields (with types, size references, attributes)

**Validation passes:**
1. Syntax validation (Lark parser)
2. Type checking (valid types, endianness)
3. Size reference validation (referenced fields exist and are integers)
4. Variable-length field rules (one at end)
5. Array element rules (self-delimiting)
6. Inheritance validation (override rules)
7. Match exhaustiveness

**CLI commands:**
- `protococo check <message_name> <hex>` - Validate message
- `protococo find <hex> [--dissect]` - Identify and parse messages
- `protococo create <message_name> [--from-json]` - Generate messages
- `protococo tree` - Show message hierarchy

**File extension:** `.coco`

---

## 16. Design Decisions Summary

**Solved problems from v0.2.0:**

1. ✅ **Removed `lengthof`**: Use explicit `field[size_field]` with auto-calculation
2. ✅ **Removed `u8[N]`**: Only `bytes[N]` for byte arrays
3. ✅ **Variable-length field rules**: Only one, at end
4. ✅ **Array element rules**: Must be self-delimiting
5. ✅ **Override compatibility**: Clear rules table
6. ✅ **Removed `if` keyword**: Not used (optional fields removed)
7. ✅ **Constant types**: Integers and strings

**Previous decisions maintained:**
- Inheritance: override only, no field addition
- Match: must be exhaustive
- Bit fields: 8-bit only
- Strings: default to ASCII
- Error handling: strict validation

**Deferred to future:**
- Namespaces/imports (v2+)
- Auto-checksum calculation (v2+)
- Validation constraints beyond types (v2+)
- Lenient parsing mode / lenient enums (v2+)
- Optional fields (v2+ if needed)
- Offset-based references for file formats (v2+) - e.g., `field @ offset_field`
- UTF-8 string encoding (v2+) - e.g., `string:utf8[N]`

---

## 17. Migration from Old .coco

**Not backward compatible** - this is a complete redesign.

Migration approach:
1. Backup old .coco files
2. Rewrite using new syntax
3. Test with new parser

**Note:** Old and new .coco formats are incompatible. The `version 1.0` header distinguishes new format files.
