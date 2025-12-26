"""
Protococo Encoder v1.0

Encodes messages to hex bytes using protocol definitions.
"""

from dataclasses import dataclass, field
from typing import Any
from collections import OrderedDict

from coco_ast import (
    CocoFile, Message, Field,
    IntegerType, BytesType, StringType, PadType, BitFieldType,
    EnumTypeRef,
    LiteralSize, FieldRefSize, VariableSize, GreedySize, FillToSize, UntilSize, SizeExpr,
    Endianness,
)


@dataclass
class FieldCategory:
    """Categorized fields for message creation."""
    fixed_fields: list[str] = field(default_factory=list)      # Have default values
    length_fields: list[str] = field(default_factory=list)     # Referenced by size specs
    input_fields: list[str] = field(default_factory=list)      # User must provide


@dataclass
class InputFieldSpec:
    """Specification for a field that needs user input."""
    name: str
    field_type: str  # "bytes", "string", "integer", etc.
    description: str = ""


class Encoder:
    """Encodes messages to hex bytes using protocol definitions."""

    def __init__(self, coco_file: CocoFile):
        self.coco_file = coco_file
        self.default_endian = coco_file.endian

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
            return list(msg.fields)

        parent = self.coco_file.get_message(msg.parent)
        if parent is None:
            raise ValueError(f"Parent message '{msg.parent}' not found")

        parent_fields = self.resolve_message(parent)
        fields = list(parent_fields)

        for override in msg.overrides:
            path = override.path
            fields = self._apply_override(fields, path, override)

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
                    # Recurse into structure_body or embedded message
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
                        result.append(f)
            else:
                result.append(f)

        return result

    def categorize_fields(self, msg: Message) -> FieldCategory:
        """Categorize message fields into fixed, length, and input fields."""
        fields = self.resolve_message(msg)
        category = FieldCategory()

        # First pass: find all fields referenced by size specs (length fields)
        # Only track simple (non-nested) field references as length fields
        referenced_fields = set()
        for f in fields:
            if isinstance(f.size, FieldRefSize) and len(f.size.field_path) == 1:
                referenced_fields.add(f.size.field_path[0])

        # Second pass: categorize each field
        for f in fields:
            # Skip padding fields - they're auto-filled
            if isinstance(f.type, PadType):
                category.fixed_fields.append(f.name)
                continue

            # Length fields - referenced by other fields
            if f.name in referenced_fields:
                category.length_fields.append(f.name)
                continue

            # Fixed fields - have default values
            if f.default_value is not None:
                category.fixed_fields.append(f.name)
                continue

            # Input fields - user must provide
            category.input_fields.append(f.name)

        return category

    def get_input_specs(self, msg: Message) -> list[InputFieldSpec]:
        """Get specifications for fields that need user input."""
        fields = self.resolve_message(msg)
        category = self.categorize_fields(msg)

        specs = []
        for f in fields:
            if f.name in category.input_fields:
                field_type = self._get_field_type_name(f.type)
                specs.append(InputFieldSpec(
                    name=f.name,
                    field_type=field_type,
                    description=f.attributes.doc if f.attributes and f.attributes.doc else ""
                ))
        return specs

    def _get_field_type_name(self, field_type) -> str:
        """Get a human-readable type name."""
        if isinstance(field_type, IntegerType):
            return field_type.base
        elif isinstance(field_type, BytesType):
            return "bytes"
        elif isinstance(field_type, StringType):
            return "string:cstr" if field_type.is_cstr else "string"
        elif isinstance(field_type, PadType):
            return "pad"
        elif isinstance(field_type, BitFieldType):
            return "bits[8]"
        elif isinstance(field_type, EnumTypeRef):
            return field_type.enum_name
        return "unknown"

    def encode_integer(self, value: int, int_type: IntegerType) -> str:
        """Encode an integer to hex string."""
        byte_size = int_type.byte_size
        endian = int_type.endian or self.default_endian

        if endian == Endianness.LITTLE:
            raw_bytes = value.to_bytes(byte_size, byteorder='little', signed=int_type.is_signed)
        else:
            raw_bytes = value.to_bytes(byte_size, byteorder='big', signed=int_type.is_signed)

        return raw_bytes.hex()

    def encode_field(self, field: Field, value: Any, context: dict) -> str:
        """Encode a single field value to hex string.

        Args:
            field: Field definition
            value: Value to encode (can be int, str, bytes, or hex string)
            context: Dict of field values for size calculation

        Returns:
            Hex string representation of the encoded field
        """
        field_type = field.type

        if isinstance(field_type, IntegerType):
            if isinstance(value, str):
                # Could be constant name or hex string
                const_val = self.get_constant_value(value)
                if const_val is not None:
                    value = const_val
                elif value.startswith("0x"):
                    value = int(value, 16)
                else:
                    value = int(value)
            return self.encode_integer(value, field_type)

        elif isinstance(field_type, EnumTypeRef):
            # Could be enum field OR message array
            enum_def = self.get_enum(field_type.enum_name)
            msg_def = self.coco_file.get_message(field_type.enum_name)

            if msg_def and field.size is not None:
                # Message array - value should be list of dicts
                if isinstance(value, list):
                    return self._encode_message_array(value, msg_def)
                elif isinstance(value, str):
                    # Raw hex string for array
                    return value.lower().replace(" ", "")
                raise ValueError(f"Message array value must be a list, got {type(value)}")

            elif enum_def:
                # Value can be enum member name or integer
                if isinstance(value, str):
                    # Check if it's "EnumName.MemberName" format
                    if "." in value:
                        _, member_name = value.split(".", 1)
                    else:
                        member_name = value
                    member = enum_def.get_member_by_name(member_name)
                    if member:
                        value = member.value
                    else:
                        raise ValueError(f"Unknown enum member: {value}")

                base_type = IntegerType(base=enum_def.base_type)
                return self.encode_integer(value, base_type)

            raise ValueError(f"Unknown type: {field_type.enum_name}")

        elif isinstance(field_type, BytesType):
            hex_value = None
            if isinstance(value, bytes):
                hex_value = value.hex()
            elif isinstance(value, str):
                # Assume hex string
                hex_value = value.lower().replace(" ", "")
            else:
                hex_value = str(value)

            # Special handling for UntilSize - ensure terminator is present
            if isinstance(field.size, UntilSize):
                # Evaluate terminator value
                from coco_ast import EnumValue
                term_val = field.size.terminator
                if isinstance(term_val, EnumValue):
                    # Look up enum value
                    enum_def = self.get_enum(term_val.enum_name)
                    if enum_def:
                        member = enum_def.get_member_by_name(term_val.member_name)
                        if member:
                            terminator_value = member.value
                        else:
                            raise ValueError(f"Unknown enum member: {term_val.enum_name}.{term_val.member_name}")
                    else:
                        raise ValueError(f"Unknown enum: {term_val.enum_name}")
                elif isinstance(term_val, int):
                    terminator_value = term_val
                else:
                    raise ValueError(f"Unsupported terminator type: {type(term_val)}")

                # Ensure the hex value ends with the terminator
                terminator_hex = f"{terminator_value & 0xFF:02x}"
                if not hex_value.endswith(terminator_hex):
                    hex_value += terminator_hex

            return hex_value

        elif isinstance(field_type, StringType):
            if isinstance(value, str):
                encoded = value.encode('ascii')
                if field_type.is_cstr:
                    encoded += b'\x00'
                return encoded.hex()
            elif isinstance(value, bytes):
                if field_type.is_cstr and not value.endswith(b'\x00'):
                    value += b'\x00'
                return value.hex()
            return str(value)

        elif isinstance(field_type, PadType):
            # Determine size
            size = self._get_field_size(field, context)
            if size is None:
                size = 1

            # Use default value or 0x00
            pad_byte = field.default_value if field.default_value is not None else 0
            return format(pad_byte & 0xFF, '02x') * size

        elif isinstance(field_type, BitFieldType):
            # Value should be a dict of bitfield values
            if isinstance(value, dict) and field.bitfield_body:
                byte_val = 0
                bit_offset = 0
                for bf in field.bitfield_body.fields:
                    bf_value = value.get(bf.name, 0)
                    mask = (1 << bf.bit_count) - 1
                    byte_val |= (bf_value & mask) << bit_offset
                    bit_offset += bf.bit_count
                return format(byte_val, '02x')
            elif isinstance(value, int):
                return format(value & 0xFF, '02x')
            return "00"

        return ""

    def _encode_message_array(self, items: list, msg_def: Message) -> str:
        """Encode an array of messages.

        Args:
            items: List of dicts, each containing field values for one message
            msg_def: Message definition for array elements

        Returns:
            Hex string of all encoded messages concatenated
        """
        result = ""
        for item in items:
            # Encode each item as a message
            item_hex = self.create_message(msg_def, item)
            result += item_hex
        return result

    def _get_field_size(self, field: Field, context: dict) -> int | None:
        """Determine the size of a field in bytes."""
        field_type = field.type

        if isinstance(field_type, IntegerType):
            return field_type.byte_size

        if isinstance(field_type, EnumTypeRef):
            enum_def = self.get_enum(field_type.enum_name)
            if enum_def:
                base_type = IntegerType(base=enum_def.base_type)
                return base_type.byte_size
            return 1

        if isinstance(field_type, BitFieldType):
            return 1

        size = field.size
        if size is None:
            return None

        if isinstance(size, LiteralSize):
            return size.value

        if isinstance(size, FieldRefSize):
            ref_value = self._resolve_field_path(size.field_path, context)
            if ref_value is not None:
                return int(ref_value)
            return None

        if isinstance(size, SizeExpr):
            return self._eval_size_expr(size, context)

        if isinstance(size, FillToSize):
            # Fill to minimum size - pad until total message reaches target size
            consumed_bytes = context.get('__consumed_bytes__', 0)
            needed_bytes = size.target_size - consumed_bytes
            # Return 0 if we've already reached or exceeded the target size
            return max(0, needed_bytes)

        return None

    def _eval_size_expr(self, expr: SizeExpr, context: dict) -> int | None:
        """Evaluate a size expression to an integer value."""
        left_val = self._eval_size_operand(expr.left, context)
        right_val = self._eval_size_operand(expr.right, context)

        if left_val is None or right_val is None:
            return None

        if expr.op == '+':
            return left_val + right_val
        elif expr.op == '-':
            return max(0, left_val - right_val)
        elif expr.op == '*':
            return left_val * right_val
        return None

    def _eval_size_operand(self, operand, context: dict) -> int | None:
        """Evaluate a size operand."""
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

        # Try the full dotted path first
        full_path = ".".join(field_path)
        if full_path in context:
            return context[full_path]

        # For simple paths, just look up directly
        if len(field_path) == 1:
            return context.get(field_path[0])

        # For nested paths, traverse the context
        current = context
        for part in field_path:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current if isinstance(current, (int, float)) else None

    def create_message(self, msg: Message, input_values: dict[str, Any] = None) -> str:
        """Create an encoded message from field values.

        Args:
            msg: Message definition
            input_values: Dict of field_name -> value for input fields

        Returns:
            Complete hex string of the encoded message
        """
        if input_values is None:
            input_values = {}

        fields = self.resolve_message(msg)
        category = self.categorize_fields(msg)

        # Use list to store encoded values by index (handles duplicate field names)
        encoded_fields = [None] * len(fields)
        field_lengths = {}  # field_name -> byte length (for size references)
        field_lengths['__consumed_bytes__'] = 0  # Track total consumed bytes for fill_to

        # First pass: encode input fields and fixed fields (except length fields)
        for i, f in enumerate(fields):
            if isinstance(f.type, PadType):
                # Padding field
                if isinstance(f.size, LiteralSize):
                    encoded = self.encode_field(f, None, field_lengths)
                    encoded_fields[i] = encoded
                    field_lengths['__consumed_bytes__'] += len(encoded) // 2
            elif f.default_value is not None and f.name not in category.length_fields:
                # Fixed field with default value
                value = f.default_value
                if isinstance(value, str):
                    const_val = self.get_constant_value(value)
                    if const_val is not None:
                        value = const_val
                encoded = self.encode_field(f, value, field_lengths)
                encoded_fields[i] = encoded
                field_lengths[f.name] = len(encoded) // 2
                field_lengths['__consumed_bytes__'] += len(encoded) // 2
            elif f.name in category.input_fields:
                # Input field
                if f.name not in input_values:
                    raise ValueError(f"Missing input value for field: {f.name}")
                value = input_values[f.name]
                encoded = self.encode_field(f, value, field_lengths)
                encoded_fields[i] = encoded
                field_lengths[f.name] = len(encoded) // 2
                field_lengths['__consumed_bytes__'] += len(encoded) // 2

        # Second pass: calculate length fields based on encoded field sizes
        for i, f in enumerate(fields):
            if f.name in category.length_fields:
                # Find what this field is the length of
                target_length = 0
                for j, other_f in enumerate(fields):
                    if (isinstance(other_f.size, FieldRefSize) and
                            len(other_f.size.field_path) == 1 and
                            other_f.size.field_path[0] == f.name):
                        # Check if it's a message array (count) or bytes (length)
                        is_message_array = False
                        if isinstance(other_f.type, EnumTypeRef):
                            msg_def = self.coco_file.get_message(other_f.type.enum_name)
                            if msg_def:
                                is_message_array = True

                        if is_message_array:
                            # For message arrays, count is the number of items
                            value = input_values.get(other_f.name, [])
                            target_length = len(value) if isinstance(value, list) else 0
                        elif encoded_fields[j] is not None:
                            # For other fields, it's byte length
                            target_length = len(encoded_fields[j]) // 2
                        break

                encoded = self.encode_field(f, target_length, field_lengths)
                encoded_fields[i] = encoded
                field_lengths[f.name] = len(encoded) // 2
                field_lengths['__consumed_bytes__'] += len(encoded) // 2

        # Third pass: encode any remaining padding fields that depend on field refs
        for i, f in enumerate(fields):
            if encoded_fields[i] is None and isinstance(f.type, PadType):
                encoded = self.encode_field(f, None, field_lengths)
                encoded_fields[i] = encoded
                field_lengths['__consumed_bytes__'] += len(encoded) // 2

        # Build final message in field order
        result = ""
        for i, f in enumerate(fields):
            if encoded_fields[i] is not None:
                result += encoded_fields[i]
            else:
                raise ValueError(f"Field not encoded: {f.name}")

        return result

    def create_message_by_name(self, message_name: str, input_values: dict[str, Any] = None) -> str:
        """Create an encoded message by message name."""
        msg = self.coco_file.get_message(message_name)
        if msg is None:
            raise ValueError(f"Message '{message_name}' not found")
        return self.create_message(msg, input_values)

    def get_json_recipe(self, msg: Message) -> dict:
        """Generate a JSON recipe template for creating a message."""
        category = self.categorize_fields(msg)
        specs = self.get_input_specs(msg)

        recipe = {
            "message_name": msg.name,
            "message_fields": []
        }

        for spec in specs:
            field_recipe = {
                "field_name": spec.name,
                "value": f"<{spec.field_type}>",
                "value_is_file_path": False,
                "value_is_hex_string": spec.field_type == "bytes",
                "should_encode": False
            }
            if spec.description:
                field_recipe["description"] = spec.description
            recipe["message_fields"].append(field_recipe)

        return recipe


def create_message(coco_file: CocoFile, message_name: str, input_values: dict = None) -> str:
    """Convenience function to create a message."""
    encoder = Encoder(coco_file)
    return encoder.create_message_by_name(message_name, input_values)


def get_json_recipe(coco_file: CocoFile, message_name: str) -> dict:
    """Convenience function to get a JSON recipe."""
    encoder = Encoder(coco_file)
    msg = coco_file.get_message(message_name)
    if msg is None:
        raise ValueError(f"Message '{message_name}' not found")
    return encoder.get_json_recipe(msg)
