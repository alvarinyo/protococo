"""
Protococo Analyzer v1.0

Decodes and validates binary messages against protocol definitions.
"""

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from coco_ast import (
    CocoFile, Message, Field,
    IntegerType, BytesType, StringType, PadType, BitFieldType,
    EnumTypeRef,
    LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, BranchDeterminedSize,
    EnumValue, MatchClause,
    Endianness,
)


@dataclass
class FieldValue:
    """Wrapper for nested field values storing both hex and decoded representations."""
    hex: str
    val: Any


@dataclass
class DecodeResult:
    """Result of decoding a single field."""
    name: str
    hex_value: str
    decoded_value: Any
    is_valid: bool
    expected_hex: str | None = None  # For fixed-value fields
    errors: list[str] = None
    is_constrained: bool = False  # True if field has enum type or default value
    is_unbounded: bool = False  # True if field consumed remaining bytes without explicit size

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


@dataclass
class ValidationResult:
    """Result of validating a complete message."""
    is_valid: bool
    message_name: str
    fields: list[DecodeResult]
    remaining_bytes: str = ""
    errors: list[str] = None
    protocol_chain: list[str] = None  # Chain of layer field names (e.g., ["eth", "ip", "tcp"])

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.protocol_chain is None:
            self.protocol_chain = []

    @property
    def total_matched_bytes(self) -> int:
        return sum(len(f.hex_value) // 2 for f in self.fields)

    @property
    def total_matched_fields(self) -> int:
        return len([f for f in self.fields if f.is_valid])

    @property
    def validated_constraints(self) -> int:
        """Count of constrained fields (enum or default value) that validated successfully."""
        return len([f for f in self.fields if f.is_valid and f.is_constrained])

    @property
    def total_structured_fields(self) -> int:
        """Count all leaf fields recursively, including nested structures.

        This gives higher scores to messages that parse bytes into structured
        fields rather than dumping them into a catch-all bytes[] field.
        """
        def count_fields(value) -> int:
            if isinstance(value, dict):
                total = 0
                for v in value.values():
                    if isinstance(v, FieldValue):
                        total += count_fields(v.val)
                    elif isinstance(v, dict):
                        total += count_fields(v)
                    else:
                        total += 1  # Leaf value
                return total
            elif isinstance(value, list):
                return sum(count_fields(item) for item in value)
            else:
                return 1  # Leaf value

        total = 0
        for field in self.fields:
            if isinstance(field.decoded_value, (dict, list)):
                total += count_fields(field.decoded_value)
            else:
                total += 1
        return total

    @property
    def minimal_array_elements(self) -> int:
        """Count array elements with single integer field (failed enum validation).

        In polymorphic arrays, elements matching the base type have just the
        discriminator field. If that field's value is an integer instead of an
        enum string (like 'TcpOptKind.NOP'), it indicates failed validation.

        This distinguishes garbage parsing from legitimate single-field elements:
        - Valid NOP option: {kind: 'TcpOptKind.NOP'} -> not counted
        - Garbage parse: {kind: 123} -> counted

        This is structural - checks value type, not field names.
        """
        def count_invalid_single_field(items: list) -> int:
            """Count array elements with 1 field whose value is an integer."""
            count = 0
            for item in items:
                if isinstance(item, dict) and len(item) == 1:
                    # Get the single field's value
                    val = next(iter(item.values()))
                    if isinstance(val, FieldValue):
                        val = val.val
                    # Count if the value is an integer (failed enum)
                    if isinstance(val, int):
                        count += 1
            return count

        def scan_value(value) -> int:
            """Recursively scan for invalid single-field array elements."""
            if isinstance(value, dict):
                total = 0
                for v in value.values():
                    if isinstance(v, FieldValue):
                        total += scan_value(v.val)
                    elif isinstance(v, (dict, list)):
                        total += scan_value(v)
                return total
            elif isinstance(value, list):
                # Count invalid single-field elements in this array
                minimal = count_invalid_single_field(value)
                # Also recurse into nested structures
                for item in value:
                    if isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, FieldValue):
                                minimal += scan_value(v.val)
                            elif isinstance(v, (dict, list)):
                                minimal += scan_value(v)
                return minimal
            return 0

        total = 0
        for field in self.fields:
            if isinstance(field.decoded_value, (dict, list)):
                total += scan_value(field.decoded_value)
        return total

    @property
    def has_unbounded_fields(self) -> bool:
        """Check if any field consumed remaining bytes without explicit size.

        Messages with unbounded fields (bytes[] with no size) require encapsulation
        from a lower layer to be meaningful. When parsed at root level without
        encapsulation, such messages are semantically incomplete.
        """
        def check_fields(fields: list[DecodeResult]) -> bool:
            for f in fields:
                if f.is_unbounded:
                    return True
            return False

        return check_fields(self.fields)


class Decoder:
    """Decodes binary messages using protocol definitions."""

    def __init__(self, coco_file: CocoFile):
        self.coco_file = coco_file
        self.default_endian = coco_file.endian
        self._protocol_chain = []  # Tracks layer field names during decoding

    def _is_layer_message(self, msg_name: str) -> bool:
        """Check if message or any of its bases is marked as layer."""
        msg = self.coco_file.get_message(msg_name)
        while msg:
            if msg.is_layer:
                return True
            if msg.parent:
                msg = self.coco_file.get_message(msg.parent)
            else:
                break
        return False

    def _get_chain_name(self, msg_name: str) -> str:
        """Get short name for protocol chain display.

        Strips common suffixes like _frame, _packet, _segment for cleaner output.
        E.g., ethernet_frame -> ethernet, ipv4_packet -> ipv4
        """
        for suffix in ('_frame', '_packet', '_segment', '_datagram', '_message'):
            if msg_name.endswith(suffix):
                return msg_name[:-len(suffix)]
        return msg_name

    def get_constant_value(self, name: str) -> int | str | None:
        """Look up a constant by name."""
        const = self.coco_file.get_constant(name)
        return const.value if const else None

    def get_enum(self, name: str):
        """Look up an enum by name."""
        return self.coco_file.get_enum(name)

    def resolve_message(self, msg: Message) -> list[Field]:
        """Resolve a message's fields, including inherited fields and overrides."""
        if msg.parent is None:
            # Base message - just return fields
            return list(msg.fields)

        # Get parent message
        parent = self.coco_file.get_message(msg.parent)
        if parent is None:
            raise ValueError(f"Parent message '{msg.parent}' not found")

        # Recursively resolve parent
        parent_fields = self.resolve_message(parent)

        # Apply overrides
        fields = list(parent_fields)
        for override in msg.overrides:
            path = override.path
            fields = self._apply_override(fields, path, override)

        # Add child's own new fields (not inherited from parent)
        fields.extend(msg.fields)

        return fields

    def _apply_override(self, fields: list[Field], path: list[str], override) -> list[Field]:
        """Apply an override at the given path in the field hierarchy."""
        if not path:
            return fields

        field_name = path[0]
        remaining_path = path[1:]

        result = []
        for f in fields:
            if f.name == field_name:
                if not remaining_path:
                    # Apply override at this level
                    if hasattr(override, 'value'):
                        # Value override
                        result.append(Field(
                            name=f.name,
                            type=f.type,
                            size=f.size,
                            default_value=override.value,
                            match_clause=f.match_clause,
                            attributes=f.attributes,
                            bitfield_body=f.bitfield_body,
                            structure_body=override.fields if hasattr(override, 'fields') else f.structure_body,
                        ))
                    else:
                        # Structure override
                        result.append(Field(
                            name=f.name,
                            type=f.type,
                            size=f.size,
                            default_value=f.default_value,
                            match_clause=f.match_clause,
                            attributes=f.attributes,
                            bitfield_body=f.bitfield_body,
                            structure_body=override.fields,
                        ))
                else:
                    # Need to recurse into structure_body or embedded message
                    if f.structure_body:
                        new_structure = self._apply_override(list(f.structure_body), remaining_path, override)
                        result.append(Field(
                            name=f.name,
                            type=f.type,
                            size=f.size,
                            default_value=f.default_value,
                            match_clause=f.match_clause,
                            attributes=f.attributes,
                            bitfield_body=f.bitfield_body,
                            structure_body=new_structure,
                        ))
                    elif isinstance(f.type, EnumTypeRef):
                        # Check if this is an embedded message type
                        msg_def = self.coco_file.get_message(f.type.enum_name)
                        if msg_def:
                            # Expand the embedded message's fields and apply override
                            embedded_fields = self.resolve_message(msg_def)
                            new_structure = self._apply_override(embedded_fields, remaining_path, override)
                            result.append(Field(
                                name=f.name,
                                type=f.type,
                                size=f.size,
                                default_value=f.default_value,
                                match_clause=f.match_clause,
                                attributes=f.attributes,
                                bitfield_body=f.bitfield_body,
                                structure_body=new_structure,
                            ))
                        else:
                            # Not a message type, can't apply nested override
                            result.append(f)
                    else:
                        # Can't apply nested override - no structure_body
                        result.append(f)
            else:
                result.append(f)

        return result

    def decode_integer(self, hex_str: str, int_type: IntegerType) -> tuple[int, bool]:
        """Decode an integer from hex string."""
        byte_size = int_type.byte_size
        expected_hex_len = byte_size * 2

        if len(hex_str) < expected_hex_len:
            return 0, False

        hex_value = hex_str[:expected_hex_len]

        # Determine endianness
        endian = int_type.endian or self.default_endian

        # Convert to bytes
        try:
            raw_bytes = bytes.fromhex(hex_value)
        except ValueError:
            return 0, False

        # Decode based on endianness
        if endian == Endianness.LITTLE:
            value = int.from_bytes(raw_bytes, byteorder='little', signed=int_type.is_signed)
        else:
            value = int.from_bytes(raw_bytes, byteorder='big', signed=int_type.is_signed)

        return value, True

    def decode_field(self, hex_str: str, field: Field, context: dict) -> DecodeResult:
        """Decode a single field from hex string.

        Args:
            hex_str: Hex string to decode from
            field: Field definition
            context: Dict of already-decoded field values (for size references)

        Returns:
            DecodeResult with decoded value and validity
        """
        field_type = field.type
        errors = []

        # Special handling for branch-determined size [*]
        # The match clause determines the size by consuming bytes
        if isinstance(field.size, BranchDeterminedSize):
            if not field.match_clause:
                return DecodeResult(
                    name=field.name,
                    hex_value="",
                    decoded_value=None,
                    is_valid=False,
                    errors=["Branch-determined size [*] requires a match clause"]
                )
            # Decode match clause and let it determine how many bytes to consume
            decoded_value, consumed_hex = self._decode_match_consuming(hex_str, field.match_clause, context)
            hex_value = hex_str[:consumed_hex]
            return DecodeResult(
                name=field.name,
                hex_value=hex_value,
                decoded_value=decoded_value,
                is_valid=True,
                errors=[]
            )

        # Determine field size
        size_bytes = self._get_field_size(field, context, len(hex_str) // 2)
        if size_bytes is None:
            return DecodeResult(
                name=field.name,
                hex_value="",
                decoded_value=None,
                is_valid=False,
                errors=["Could not determine field size"]
            )

        # Special handling for cstr with variable size - find null terminator
        if (isinstance(field_type, StringType) and field_type.is_cstr and
                isinstance(field.size, VariableSize)):
            # Search for null byte in remaining hex
            try:
                raw_bytes = bytes.fromhex(hex_str)
                null_idx = raw_bytes.find(b'\x00')
                if null_idx >= 0:
                    size_bytes = null_idx + 1  # Include the null byte
                # If no null found, consume all remaining (original behavior)
            except ValueError:
                pass

        hex_len = size_bytes * 2
        if len(hex_str) < hex_len:
            return DecodeResult(
                name=field.name,
                hex_value=hex_str,
                decoded_value=None,
                is_valid=False,
                errors=[f"Not enough bytes: need {size_bytes}, have {len(hex_str) // 2}"]
            )

        hex_value = hex_str[:hex_len]
        decoded_value = None
        is_valid = True
        expected_hex = None

        # Decode based on type
        if isinstance(field_type, IntegerType):
            decoded_value, ok = self.decode_integer(hex_value, field_type)
            if not ok:
                is_valid = False
                errors.append("Failed to decode integer")

            # Check enum type reference
            if isinstance(field.type, EnumTypeRef):
                enum_def = self.get_enum(field.type.enum_name)
                if enum_def:
                    member = enum_def.get_member_by_value(decoded_value)
                    if member:
                        decoded_value = f"{enum_def.name}.{member.name}"
                    else:
                        is_valid = False
                        errors.append(f"Value {decoded_value} not in enum {enum_def.name}")

        elif isinstance(field_type, EnumTypeRef):
            # Could be enum field, message array, or single embedded message
            enum_def = self.get_enum(field_type.enum_name)
            msg_def = self.coco_file.get_message(field_type.enum_name)

            if msg_def and field.size is not None:
                # Message array - decode as array of messages
                decoded_value, consumed_bytes = self._decode_message_array(hex_value, msg_def, field, context)
                # Update hex_value to only include consumed bytes
                hex_value = hex_value[:consumed_bytes * 2]
            elif msg_def and field.size is None:
                # Single embedded message
                # Track layer in protocol chain
                if self._is_layer_message(msg_def.name):
                    self._protocol_chain.append(field.name)
                if field.structure_body:
                    # Use overridden structure instead of message definition
                    decoded_value, structure_valid = self._decode_structure(
                        hex_value, field.structure_body, context, track_validity=True
                    )
                    if not structure_valid:
                        is_valid = False
                    consumed_bytes = sum(
                        self._get_field_size(f, context, len(hex_value) // 2) or 0
                        for f in field.structure_body
                    )
                else:
                    decoded_value, consumed_bytes = self._decode_embedded_message(hex_value, msg_def, context)
                # Update hex_value to only include consumed bytes
                hex_value = hex_value[:consumed_bytes * 2]
            elif enum_def:
                # Enum field - decode as integer using enum's base type
                base_type = IntegerType(base=enum_def.base_type)
                int_val, ok = self.decode_integer(hex_value, base_type)
                if ok:
                    member = enum_def.get_member_by_value(int_val)
                    if member:
                        decoded_value = f"{enum_def.name}.{member.name}"
                    else:
                        decoded_value = int_val
                        is_valid = False
                        errors.append(f"Value {int_val} not in enum {enum_def.name}")
                else:
                    is_valid = False
                    errors.append("Failed to decode enum value")
            else:
                errors.append(f"Type '{field_type.enum_name}' not found (not an enum or message)")
                is_valid = False

        elif isinstance(field_type, BytesType):
            decoded_value = hex_value
            # Handle match clause for structure
            if field.match_clause:
                decoded_value = self._decode_match(hex_value, field.match_clause, context)
            elif field.structure_body:
                decoded_value = self._decode_structure(hex_value, field.structure_body, context)

        elif isinstance(field_type, StringType):
            try:
                raw_bytes = bytes.fromhex(hex_value)
                if field_type.is_cstr:
                    # C-string: read until null
                    null_idx = raw_bytes.find(b'\x00')
                    if null_idx >= 0:
                        decoded_value = raw_bytes[:null_idx].decode('ascii', errors='replace')
                    else:
                        decoded_value = raw_bytes.decode('ascii', errors='replace')
                else:
                    decoded_value = raw_bytes.decode('ascii', errors='replace')
            except Exception as e:
                decoded_value = hex_value
                errors.append(f"Failed to decode string: {e}")

        elif isinstance(field_type, PadType):
            decoded_value = None  # Padding is discarded

            # Validate if default value is set
            if field.default_value is not None:
                expected_byte = field.default_value & 0xFF
                expected_hex = (format(expected_byte, '02x') * size_bytes).lower()
                if hex_value.lower() != expected_hex:
                    is_valid = False
                    errors.append(f"Padding mismatch: expected {expected_hex}, got {hex_value}")

        elif isinstance(field_type, BitFieldType):
            # Parse multi-byte value with proper endianness
            raw_bytes = bytes.fromhex(hex_value)
            endian = self.default_endian
            if endian == Endianness.LITTLE:
                int_val = int.from_bytes(raw_bytes, byteorder='little')
            else:
                int_val = int.from_bytes(raw_bytes, byteorder='big')
            decoded_value = self._decode_bitfield(int_val, field, size_bytes)

        else:
            decoded_value = hex_value

        # Check fixed value
        if field.default_value is not None and not isinstance(field_type, PadType):
            expected_value = field.default_value
            # Resolve constant reference
            if isinstance(expected_value, str):
                const_val = self.get_constant_value(expected_value)
                if const_val is not None:
                    expected_value = const_val

            if isinstance(expected_value, int) and isinstance(field_type, IntegerType):
                # Compare decoded value to expected
                expected_hex = self._encode_integer(expected_value, field_type)
                if hex_value.lower() != expected_hex.lower():
                    is_valid = False
                    errors.append(f"Value mismatch: expected {expected_hex}, got {hex_value}")

            elif isinstance(expected_value, EnumValue):
                # Compare enum value - check if decoded matches expected
                expected_str = f"{expected_value.enum_name}.{expected_value.member_name}"
                if decoded_value != expected_str:
                    is_valid = False
                    errors.append(f"Enum mismatch: expected {expected_str}, got {decoded_value}")

        # Determine if field has constraints (enum type, default value, or embedded message with constraints)
        is_constrained = False
        if field.default_value is not None:
            is_constrained = True
        elif isinstance(field.type, EnumTypeRef):
            # Check if it's an enum (not a message type)
            if self.get_enum(field.type.enum_name):
                is_constrained = True
            else:
                # Check if it's an embedded message with constraints
                embedded_msg = self.coco_file.get_message(field.type.enum_name)
                if embedded_msg and self._message_has_constraints(embedded_msg):
                    is_constrained = True

        # Determine if field is unbounded (bytes[] or string[] with no explicit size, or greedy [...])
        # Such fields require encapsulation from a lower layer to be meaningful
        # Exception: fields with match clauses have implicit structure from nested messages
        # Exception: pad[...] is not semantically meaningful content, so it's not penalized
        is_unbounded = (
            isinstance(field.size, (VariableSize, GreedySize)) and
            isinstance(field_type, (BytesType, StringType)) and
            not isinstance(field_type, PadType) and  # padding is not meaningful content
            not (isinstance(field_type, StringType) and field_type.is_cstr) and  # cstr has implicit delimiter
            not field.match_clause  # match clause provides structure via nested messages
        )

        return DecodeResult(
            name=field.name,
            hex_value=hex_value,
            decoded_value=decoded_value,
            is_valid=is_valid,
            expected_hex=expected_hex,
            errors=errors,
            is_constrained=is_constrained,
            is_unbounded=is_unbounded,
        )

    def _get_message_fixed_size(self, msg: Message, context: dict) -> int | None:
        """Calculate the fixed size of a message in bytes.

        Returns None if the message has variable-length fields that can't be resolved.
        """
        fields = self.resolve_message(msg)
        total = 0
        local_context = dict(context)

        for field in fields:
            field_size = self._get_field_size(field, local_context, 0)
            if field_size is None:
                return None  # Can't determine size
            total += field_size

        return total

    def _message_has_constraints(self, msg: Message) -> bool:
        """Check if a message has any constrained fields (enum or default value)."""
        fields = self.resolve_message(msg)
        for field in fields:
            if field.default_value is not None:
                return True
            if isinstance(field.type, EnumTypeRef):
                if self.get_enum(field.type.enum_name):
                    return True
                # Check if it's an embedded message with constraints
                embedded_msg = self.coco_file.get_message(field.type.enum_name)
                if embedded_msg and self._message_has_constraints(embedded_msg):
                    return True
        return False

    def _get_field_size(self, field: Field, context: dict, remaining_bytes: int) -> int | None:
        """Determine the size of a field in bytes."""
        field_type = field.type

        # Fixed-size types
        if isinstance(field_type, IntegerType):
            return field_type.byte_size

        if isinstance(field_type, EnumTypeRef):
            enum_def = self.get_enum(field_type.enum_name)
            if enum_def:
                base_type = IntegerType(base=enum_def.base_type)
                return base_type.byte_size
            # Check if it's a message type
            msg_def = self.coco_file.get_message(field_type.enum_name)
            if msg_def:
                if field.size is not None:
                    # Message array - evaluate size expression for byte count
                    if isinstance(field.size, LiteralSize):
                        # Literal is element count, not byte count - use remaining
                        return remaining_bytes
                    elif isinstance(field.size, FieldRefSize):
                        # Field ref could be element count or byte count
                        ref_value = self._resolve_field_path(field.size.field_path, context)
                        if ref_value is not None:
                            return remaining_bytes
                        return None  # Can't resolve size
                    elif isinstance(field.size, SizeExpr):
                        # Size expression is byte count
                        byte_count = self._eval_size_expr(field.size, context)
                        if byte_count is not None:
                            return byte_count
                        return None  # Can't resolve size expression
                    else:
                        # VariableSize - consume remaining
                        return remaining_bytes
                elif field.structure_body:
                    # Embedded message with overridden structure - calculate from structure_body
                    total = 0
                    for f in field.structure_body:
                        f_size = self._get_field_size(f, context, 0)
                        if f_size is None:
                            return None
                        total += f_size
                    return total
                else:
                    # Single embedded message - try fixed size, fall back to remaining
                    fixed_size = self._get_message_fixed_size(msg_def, context)
                    if fixed_size is not None:
                        return fixed_size
                    # Message has variable-length fields - consume remaining bytes
                    return remaining_bytes if remaining_bytes > 0 else None
            return 1  # Default to 1 byte

        if isinstance(field_type, BitFieldType):
            return field_type.bit_count // 8  # bits[N] is N/8 bytes

        # Variable-size types - check size spec
        size = field.size
        if size is None:
            return remaining_bytes  # Consume rest

        if isinstance(size, LiteralSize):
            return size.value

        if isinstance(size, FieldRefSize):
            ref_value = self._resolve_field_path(size.field_path, context)
            if ref_value is not None:
                return int(ref_value)
            return None

        if isinstance(size, SizeExpr):
            return self._eval_size_expr(size, context)

        if isinstance(size, GreedySize):
            # Greedy size - consume all remaining bytes from outer layer
            # 0 bytes is valid (nothing left to consume)
            return remaining_bytes

        if isinstance(size, VariableSize):
            # Variable size can't be determined without remaining_bytes context
            # Note: In new syntax, bare [] should have been converted to BranchDeterminedSize
            # This is a fallback for safety
            return remaining_bytes if remaining_bytes > 0 else None

        return remaining_bytes if remaining_bytes > 0 else None

    def _eval_size_expr(self, expr: SizeExpr, context: dict) -> int | None:
        """Evaluate a size expression to an integer value."""
        left_val = self._eval_size_operand(expr.left, context)
        right_val = self._eval_size_operand(expr.right, context)

        if left_val is None or right_val is None:
            return None

        if expr.op == '+':
            return left_val + right_val
        elif expr.op == '-':
            return max(0, left_val - right_val)  # Don't allow negative sizes
        elif expr.op == '*':
            return left_val * right_val
        return None

    def _eval_size_operand(self, operand, context: dict) -> int | None:
        """Evaluate a size operand (LiteralSize, FieldRefSize, or SizeExpr)."""
        if isinstance(operand, LiteralSize):
            return operand.value
        elif isinstance(operand, FieldRefSize):
            ref_value = self._resolve_field_path(operand.field_path, context)
            if ref_value is not None:
                return int(ref_value)
            return None
        elif isinstance(operand, SizeExpr):
            return self._eval_size_expr(operand, context)
        return None

    def _resolve_field_path(self, field_path: list[str], context: dict) -> int | None:
        """Resolve a field path like ['hdr', 'total_length'] to a value from context."""
        if not field_path:
            return None

        # Try the full dotted path first (for backward compatibility with flat keys)
        full_path = ".".join(field_path)
        if full_path in context:
            return context[full_path]

        # For simple paths, just look up directly
        if len(field_path) == 1:
            val = context.get(field_path[0])
            # Extract from FieldValue if present
            if isinstance(val, FieldValue):
                val = val.val
            return val

        # For nested paths, traverse the context
        # E.g., ['hdr', 'total_length'] -> look for context['hdr']['total_length']
        current = context
        for part in field_path:
            # Extract actual value from FieldValue if present
            if isinstance(current, FieldValue):
                current = current.val
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        # Extract final value from FieldValue if present
        if isinstance(current, FieldValue):
            current = current.val
        return current if isinstance(current, (int, float)) else None

    def _flatten_to_context(self, prefix: str, data: dict, context: dict) -> None:
        """Flatten a nested dict into dotted-path context entries.

        E.g., _flatten_to_context('hdr', {'total_length': 37}, context)
        adds context['hdr.total_length'] = 37
        """
        for key, value in data.items():
            full_key = f"{prefix}.{key}"
            # Extract actual value from FieldValue if present
            actual_val = value.val if isinstance(value, FieldValue) else value
            if isinstance(actual_val, dict):
                self._flatten_to_context(full_key, actual_val, context)
            elif isinstance(actual_val, (int, float, str)):
                # Store int, float, and string values (including enum decoded values)
                context[full_key] = actual_val

    def _encode_integer(self, value: int, int_type: IntegerType) -> str:
        """Encode an integer to hex string."""
        byte_size = int_type.byte_size
        endian = int_type.endian or self.default_endian

        if endian == Endianness.LITTLE:
            raw_bytes = value.to_bytes(byte_size, byteorder='little', signed=int_type.is_signed)
        else:
            raw_bytes = value.to_bytes(byte_size, byteorder='big', signed=int_type.is_signed)

        return raw_bytes.hex()

    def _decode_bitfield(self, int_val: int, field: Field, byte_count: int = 1) -> dict:
        """Decode a bitfield into individual fields.

        Args:
            int_val: Integer value of the bitfield
            field: Field definition with bitfield_body
            byte_count: Number of bytes (for hex formatting)
        """
        hex_width = byte_count * 2
        full_hex = format(int_val, f'0{hex_width}x')
        if not field.bitfield_body:
            return {"raw": FieldValue(full_hex, int_val)}

        result = {}
        bit_offset = 0
        for bf in field.bitfield_body.fields:
            mask = (1 << bf.bit_count) - 1
            value = (int_val >> bit_offset) & mask
            # For individual bits/sub-fields, hex is just the masked value
            bit_hex = format(value, 'x') if value > 0 else '0'
            result[bf.name] = FieldValue(bit_hex, value)
            bit_offset += bf.bit_count

        return result

    def _resolve_path(self, path: str, context: dict):
        """Resolve a dotted path like 'header.protocol' in the context."""
        parts = path.split('.')
        value = context
        for part in parts:
            # Extract actual value from FieldValue if present
            if isinstance(value, FieldValue):
                value = value.val
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
            if value is None:
                return None
        # Extract final value from FieldValue if present
        if isinstance(value, FieldValue):
            value = value.val
        return value

    def _decode_match(self, hex_str: str, match_clause: MatchClause, context: dict) -> dict:
        """Decode a matched field based on discriminator value."""
        # Resolve dotted path discriminator (e.g., "header.protocol")
        discriminator_value = self._resolve_path(match_clause.discriminator, context)

        # Find matching branch
        matching_branch = None
        default_branch = None

        for branch in match_clause.branches:
            if branch.pattern is None:
                default_branch = branch
            elif isinstance(branch.pattern, EnumValue):
                # Check enum value match
                enum_str = f"{branch.pattern.enum_name}.{branch.pattern.member_name}"
                if discriminator_value == enum_str:
                    matching_branch = branch
                    break
                # Also check raw integer value
                enum_def = self.get_enum(branch.pattern.enum_name)
                if enum_def:
                    member = enum_def.get_member_by_name(branch.pattern.member_name)
                    if member and discriminator_value == member.value:
                        matching_branch = branch
                        break
            elif branch.pattern == discriminator_value:
                matching_branch = branch
                break

        branch = matching_branch or default_branch
        if branch and branch.fields:
            return self._decode_structure(hex_str, branch.fields, context)

        return {"raw": FieldValue(hex_str, hex_str)}

    def _decode_match_consuming(self, hex_str: str, match_clause: MatchClause, context: dict) -> tuple[dict, int]:
        """Decode a match clause and return (decoded_value, consumed_hex_chars).

        Used for branch-determined size [*] where the match branch determines
        the size of the containing field.

        Args:
            hex_str: Full remaining hex string (not pre-sliced)
            match_clause: The match clause to evaluate
            context: Context with already decoded values

        Returns:
            Tuple of (decoded dict, consumed hex characters count)
        """
        # Resolve dotted path discriminator (e.g., "header.protocol")
        discriminator_value = self._resolve_path(match_clause.discriminator, context)

        # Find matching branch
        matching_branch = None
        default_branch = None

        for branch in match_clause.branches:
            if branch.pattern is None:
                default_branch = branch
            elif isinstance(branch.pattern, EnumValue):
                # Check enum value match
                enum_str = f"{branch.pattern.enum_name}.{branch.pattern.member_name}"
                if discriminator_value == enum_str:
                    matching_branch = branch
                    break
                # Also check raw integer value
                enum_def = self.get_enum(branch.pattern.enum_name)
                if enum_def:
                    member = enum_def.get_member_by_name(branch.pattern.member_name)
                    if member and discriminator_value == member.value:
                        matching_branch = branch
                        break
            elif branch.pattern == discriminator_value:
                matching_branch = branch
                break

        branch = matching_branch or default_branch
        if branch and branch.fields:
            # Decode branch fields and track consumed bytes
            result, consumed = self._decode_structure_consuming(hex_str, branch.fields, context)
            return result, consumed

        # Empty branch - consume 0 bytes
        return {}, 0

    def _decode_structure_consuming(self, hex_str: str, fields: list[Field], parent_context: dict) -> tuple[dict, int]:
        """Decode a structure and return (decoded_value, consumed_hex_chars).

        Similar to _decode_structure but returns consumed hex char count for
        branch-determined sizing.
        """
        result = {}
        context = dict(parent_context)
        offset = 0

        for field in fields:
            remaining = hex_str[offset:]
            if not remaining:
                break

            decode_result = self.decode_field(remaining, field, context)
            result[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)
            context[field.name] = decode_result.decoded_value
            if isinstance(decode_result.decoded_value, dict):
                self._flatten_to_context(field.name, decode_result.decoded_value, context)

            offset += len(decode_result.hex_value)

        return result, offset

    def _decode_structure(self, hex_str: str, fields: list[Field], parent_context: dict, track_validity: bool = False) -> dict | tuple[dict, bool]:
        """Decode a nested structure.

        Args:
            hex_str: Hex string to decode
            fields: List of fields to decode
            parent_context: Context with already decoded values
            track_validity: If True, return (dict, is_valid) tuple

        Returns:
            dict of FieldValue objects, or (dict, is_valid) if track_validity=True
        """
        result = {}
        context = dict(parent_context)
        offset = 0
        all_valid = True

        for field in fields:
            remaining = hex_str[offset:]
            if not remaining:
                break

            decode_result = self.decode_field(remaining, field, context)
            # Store both hex and decoded value for display flexibility
            result[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)
            # Context still uses plain values for size references and match lookups
            context[field.name] = decode_result.decoded_value
            # Flatten dict values for dotted path lookups (e.g., data_offset_flags.data_offset)
            if isinstance(decode_result.decoded_value, dict):
                self._flatten_to_context(field.name, decode_result.decoded_value, context)

            if not decode_result.is_valid:
                all_valid = False

            offset += len(decode_result.hex_value)

        if track_validity:
            return result, all_valid
        return result

    def _decode_embedded_message(self, hex_str: str, msg_def: Message, context: dict) -> tuple[dict, int]:
        """Decode a single embedded message.

        Args:
            hex_str: Hex string containing the message data
            msg_def: Message definition to decode
            context: Context with field values

        Returns:
            Tuple of (decoded message dict with FieldValue objects, consumed byte count)
        """
        fields = self.resolve_message(msg_def)
        result = {}
        offset = 0
        local_context = dict(context)

        for field in fields:
            remaining = hex_str[offset:]
            if not remaining:
                break

            decode_result = self.decode_field(remaining, field, local_context)
            # Store both hex and decoded value for display flexibility
            result[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)

            # Store decoded value in local context for subsequent field refs (match, size)
            if isinstance(decode_result.decoded_value, (int, float)):
                local_context[field.name] = decode_result.decoded_value
            elif isinstance(decode_result.decoded_value, dict):
                # Bitfield or embedded message - store dict and flatten for dotted path refs
                local_context[field.name] = decode_result.decoded_value
                self._flatten_to_context(field.name, decode_result.decoded_value, local_context)
            elif isinstance(decode_result.decoded_value, str):
                # String values including enum decoded values (e.g., "EtherType.IPV4")
                local_context[field.name] = decode_result.decoded_value
            elif isinstance(field.type, IntegerType) and decode_result.hex_value:
                try:
                    local_context[field.name] = int(decode_result.hex_value, 16)
                except ValueError:
                    pass

            offset += len(decode_result.hex_value)

        return result, offset // 2

    def _decode_message_array(self, hex_str: str, msg_def: Message, field: Field, context: dict) -> tuple[list, int]:
        """Decode an array of messages.

        Supports polymorphic arrays: if msg_def has subtypes, each element
        is parsed by trying all subtypes and picking the best match.

        Args:
            hex_str: Hex string containing the array data
            msg_def: Message definition for array elements
            field: Field definition (contains size spec for count)
            context: Context with field values (for count reference)

        Returns:
            Tuple of (list of decoded message dictionaries, consumed byte count)
        """
        result = []
        offset = 0

        # Determine count
        count = None
        if isinstance(field.size, LiteralSize):
            count = field.size.value
        elif isinstance(field.size, FieldRefSize):
            count = self._resolve_field_path(field.size.field_path, context) or 0
        # VariableSize means decode until end

        # Get subtypes for polymorphic parsing
        subtypes = self.coco_file.get_subtypes(msg_def.name)
        if subtypes:
            # Use only subtypes (sorted by inheritance depth, most specific first)
            # Base type is used as fallback only if no subtype matches
            candidate_types = sorted(subtypes, key=lambda m: -self._get_inheritance_depth(m.name))
            fallback_type = msg_def
        else:
            # No subtypes - just use base type
            candidate_types = [msg_def]
            fallback_type = None

        element_idx = 0
        while offset < len(hex_str):
            if count is not None and element_idx >= count:
                break

            remaining = hex_str[offset:]
            if not remaining:
                break

            # Try each candidate type and pick the best match
            best_result = None
            best_hex_len = 0

            # Save chain before trying candidates (validate_message resets it)
            saved_chain = list(self._protocol_chain)

            for candidate in candidate_types:
                # Allow remaining bytes for array elements (they consume only what they need)
                candidate_result = self.validate_message(candidate, remaining, allow_remaining=True)

                # Calculate consumed bytes for this candidate
                candidate_hex_len = sum(len(f.hex_value) for f in candidate_result.fields)

                # Skip if no bytes consumed (would cause infinite loop)
                if candidate_hex_len == 0:
                    continue

                # Only accept valid candidates with validated constraints
                # (subtypes should have default values that validate)
                if not candidate_result.is_valid:
                    continue

                # Pick this candidate if it has more validated constraints
                if best_result is None:
                    best_result = candidate_result
                    best_hex_len = candidate_hex_len
                elif candidate_result.validated_constraints > best_result.validated_constraints:
                    best_result = candidate_result
                    best_hex_len = candidate_hex_len

            # If no subtype matched, try the fallback (base) type
            if best_result is None and fallback_type is not None:
                fallback_result = self.validate_message(fallback_type, remaining, allow_remaining=True)
                fallback_hex_len = sum(len(f.hex_value) for f in fallback_result.fields)
                if fallback_hex_len > 0:
                    best_result = fallback_result
                    best_hex_len = fallback_hex_len

            # Restore chain after trying candidates
            self._protocol_chain = saved_chain

            if best_result is None or best_hex_len == 0:
                # No candidate could parse, stop
                break

            # Extract decoded values as a dict with FieldValue objects
            element_dict = {}
            for field_result in best_result.fields:
                element_dict[field_result.name] = FieldValue(field_result.hex_value, field_result.decoded_value)

            result.append(element_dict)
            offset += best_hex_len
            element_idx += 1

        # Return list and consumed byte count (offset is in hex chars, divide by 2)
        return result, offset // 2

    def validate_message(self, msg: Message, hex_str: str, allow_remaining: bool = False) -> ValidationResult:
        """Validate a hex message against a message definition.

        Args:
            msg: Message definition
            hex_str: Hex string to validate
            allow_remaining: If True, don't fail on remaining bytes (for polymorphic arrays)

        Returns:
            ValidationResult with field-by-field results
        """
        hex_str = hex_str.lower().replace(" ", "")
        fields = self.resolve_message(msg)

        # Reset protocol chain for this validation
        self._protocol_chain = []

        # Add root layer message to chain (uses message name since there's no field name)
        if msg.is_layer:
            self._protocol_chain.append(self._get_chain_name(msg.name))

        results = []
        context = {}
        offset = 0
        all_valid = True

        for field in fields:
            remaining = hex_str[offset:]
            # Allow empty remaining for GreedySize and BranchDeterminedSize
            # (BranchDeterminedSize can consume 0 bytes for empty match branches)
            # (GreedySize consumes all remaining, including 0 bytes)
            if not remaining and not isinstance(field.size, (GreedySize, BranchDeterminedSize)):
                # Not enough bytes
                results.append(DecodeResult(
                    name=field.name,
                    hex_value="",
                    decoded_value=None,
                    is_valid=False,
                    errors=["No bytes remaining"]
                ))
                all_valid = False
                continue

            result = self.decode_field(remaining, field, context)
            results.append(result)

            # Update context with decoded value
            if isinstance(result.decoded_value, int):
                context[field.name] = result.decoded_value
            elif isinstance(result.decoded_value, dict):
                # Embedded message - store the dict and add flattened entries
                context[field.name] = result.decoded_value
                self._flatten_to_context(field.name, result.decoded_value, context)
            elif isinstance(result.decoded_value, str) and result.decoded_value.startswith("0x"):
                pass  # Keep as hex
            elif isinstance(field.type, IntegerType):
                # Store integer value for size references
                try:
                    context[field.name] = int(result.hex_value, 16) if result.hex_value else 0
                except ValueError:
                    pass

            # Also store raw integer for enum fields
            if isinstance(field.type, EnumTypeRef) and result.hex_value:
                enum_def = self.get_enum(field.type.enum_name)
                if enum_def:
                    base_type = IntegerType(base=enum_def.base_type)
                    int_val, _ = self.decode_integer(result.hex_value, base_type)
                    context[field.name] = int_val

            if not result.is_valid:
                all_valid = False

            offset += len(result.hex_value)

        remaining_bytes = hex_str[offset:]

        # Validity is based on field validation only, not remaining bytes.
        # Remaining bytes are tracked separately and used as a ranking penalty
        # in identify_message(), but don't make the message "invalid".
        # For polymorphic arrays (allow_remaining=True), this is already the behavior.
        is_fully_valid = all_valid

        return ValidationResult(
            is_valid=is_fully_valid,
            message_name=msg.name,
            fields=results,
            remaining_bytes=remaining_bytes,
            protocol_chain=list(self._protocol_chain),  # Copy the chain
        )

    def validate_by_name(self, message_name: str, hex_str: str) -> ValidationResult:
        """Validate a hex message by message name."""
        msg = self.coco_file.get_message(message_name)
        if msg is None:
            return ValidationResult(
                is_valid=False,
                message_name=message_name,
                fields=[],
                errors=[f"Message '{message_name}' not found"]
            )
        return self.validate_message(msg, hex_str)

    def identify_message(self, hex_str: str) -> list[ValidationResult]:
        """Try to identify which message type matches the hex string.

        Returns list of validation results, sorted by best match.
        """
        results = []

        for msg in self.coco_file.messages:
            result = self.validate_message(msg, hex_str)
            results.append(result)

        # Sort by: valid first, penalize unbounded fields at root, penalize remaining bytes,
        # then by validated constraints, then penalize invalid nested elements, then by structured fields,
        # then by matched bytes, then by inheritance depth
        results.sort(key=lambda r: (
            not r.is_valid,
            r.has_unbounded_fields,       # Penalize messages with unbounded bytes[] at root level
            len(r.remaining_bytes) > 0,   # Strongly prefer complete parses (no remaining bytes)
            -r.validated_constraints,     # Prefer messages with more validated enum/default fields
            r.minimal_array_elements,     # Penalize messages with many single-field array elements
            -r.total_structured_fields,   # Prefer messages that parse into more leaf fields
            -r.total_matched_bytes,
            -self._get_inheritance_depth(r.message_name) if r.is_valid else 0,  # Only prefer children when valid
        ))

        return results

    def _get_inheritance_depth(self, message_name: str) -> int:
        """Get the inheritance depth of a message (0 = base, 1 = one parent, etc.)."""
        depth = 0
        msg = self.coco_file.get_message(message_name)
        while msg and msg.parent:
            depth += 1
            msg = self.coco_file.get_message(msg.parent)
        return depth


def validate_message(coco_file: CocoFile, message_name: str, hex_str: str) -> ValidationResult:
    """Convenience function to validate a message."""
    decoder = Decoder(coco_file)
    return decoder.validate_by_name(message_name, hex_str)


def identify_message(coco_file: CocoFile, hex_str: str) -> list[ValidationResult]:
    """Convenience function to identify a message."""
    decoder = Decoder(coco_file)
    return decoder.identify_message(hex_str)
