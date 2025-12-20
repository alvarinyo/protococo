"""
Protococo Parser v1.0

Uses Lark to parse .coco files and transform them into AST nodes.
"""

from pathlib import Path
from lark import Lark, Transformer, v_args, Token
from coco_ast import (
    CocoFile, Constant, EnumDef, EnumMember, Message, Field,
    IntegerType, BytesType, StringType, PadType, BitFieldType,
    EnumTypeRef, MessageTypeRef,
    LiteralSize, FieldRefSize, VariableSize, SizeExpr,
    EnumValue, FieldAttributes, DisplayFormat,
    MatchClause, MatchBranch,
    ValueOverride, StructureOverride,
    Endianness,
    BitField, BitFieldBody,
)


# Load grammar from file
GRAMMAR_PATH = Path(__file__).parent / "grammar.lark"


def get_parser() -> Lark:
    """Create and return the Lark parser."""
    with open(GRAMMAR_PATH) as f:
        grammar = f.read()
    return Lark(grammar, start="start", parser="lalr")


class CocoTransformer(Transformer):
    """Transform Lark parse tree into AST nodes."""

    # === Terminals ===

    def IDENT(self, token):
        return str(token)

    def HEX_NUMBER(self, token):
        return int(str(token), 16)

    def DEC_NUMBER(self, token):
        return int(str(token))

    def BIN_NUMBER(self, token):
        return int(str(token), 2)

    def STRING(self, token):
        # Remove quotes
        return str(token)[1:-1]

    def VERSION_NUMBER(self, token):
        return str(token)

    def ENDIAN(self, token):
        return Endianness.LITTLE if str(token) == "le" else Endianness.BIG

    # === Header ===

    def version_decl(self, items):
        return ("version", items[0])

    def endian_decl(self, items):
        return ("endian", items[0])

    def header_section(self, items):
        result = {}
        for key, value in items:
            result[key] = value
        return result

    # === Constants ===

    def const_value(self, items):
        return items[0]

    def const_def(self, items):
        name, value = items
        return Constant(name=name, value=value)

    # === Enums ===

    def enum_member(self, items):
        name, value = items
        return EnumMember(name=name, value=value)

    def enum_members(self, items):
        return list(items)

    def base_type(self, items):
        # items[0] is already a string from INT_TYPE
        return items[0]

    def enum_def(self, items):
        name, base_type, members = items
        return EnumDef(name=name, base_type=base_type, members=members)

    # === Field Types ===

    def INT_TYPE(self, token):
        return str(token)

    def integer_type(self, items):
        return items[0]  # Already a string from INT_TYPE

    def endian_suffix(self, items):
        return items[0]

    def string_encoding(self, items):
        return "cstr"

    def bitfield_type(self, items):
        # items[0] is the INT token with the bit count
        bit_count = int(items[0])
        if bit_count % 8 != 0:
            raise ValueError(f"bits[{bit_count}]: bit count must be a multiple of 8")
        return BitFieldType(bit_count=bit_count)

    def BYTES_KW(self, token):
        return "bytes"

    def STRING_KW(self, token):
        return "string"

    def PAD_KW(self, token):
        return "pad"

    def builtin_type(self, items):
        """Handle builtin types: integer_type, bytes, string, pad, bits

        Returns tuple of (FieldType, SizeSpec or None)
        """
        if len(items) == 0:
            return (None, None)

        first = items[0]

        # Integer type with optional endianness
        if isinstance(first, str) and first in ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"):
            endian = items[1] if len(items) > 1 and isinstance(items[1], Endianness) else None
            return (IntegerType(base=first, endian=endian), None)

        # BitFieldType
        if isinstance(first, BitFieldType):
            return (first, None)

        # bytes with optional size
        if first == "bytes":
            size = None
            for item in items[1:]:
                if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                    size = item
            return (BytesType(), size)

        # string with optional encoding and size
        if first == "string":
            is_cstr = False
            size = None
            for item in items[1:]:
                if item == "cstr":
                    is_cstr = True
                elif isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                    size = item
            return (StringType(is_cstr=is_cstr), size)

        # pad with size
        if first == "pad":
            size = None
            for item in items[1:]:
                if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                    size = item
            return (PadType(), size)

        return (first, None)

    def message_item(self, items):
        return items[0]

    def typed_field_def(self, items):
        """Handle field with type reference: TypeName field_name ..."""
        type_name = items[0]  # IDENT for type
        field_name = items[1]  # IDENT for field

        size = None
        default = None
        match = None
        attrs = None

        for item in items[2:]:
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        return Field(
            name=field_name,
            type=EnumTypeRef(enum_name=type_name),
            size=size,
            default_value=default,
            match_clause=match,
            attributes=attrs,
        )

    def field_type(self, items):
        if len(items) == 0:
            return None

        first = items[0]

        # Check if it's an integer type string
        if isinstance(first, str) and first in ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"):
            endian = items[1] if len(items) > 1 and isinstance(items[1], Endianness) else None
            return IntegerType(base=first, endian=endian)

        # Check for Token objects (bytes/string/pad)
        if isinstance(first, Token):
            token_str = str(first)
            if token_str == "bytes":
                return BytesType()
            if token_str == "string":
                is_cstr = len(items) > 1 and items[1] == "cstr"
                return StringType(is_cstr=is_cstr)
            if token_str == "pad":
                return PadType()

        # BitFieldType
        if isinstance(first, BitFieldType):
            return first

        # Otherwise it's an identifier (enum or message reference)
        if isinstance(first, str):
            return EnumTypeRef(enum_name=first)

        return first

    # === Size Spec ===

    def field_ref(self, items):
        """Handle field reference: IDENT or IDENT.IDENT.IDENT..."""
        return [str(item) for item in items]

    def size_value(self, items):
        if len(items) == 0:
            return VariableSize()
        val = items[0]
        # If it's already a SizeSpec (from expression), return it
        if isinstance(val, (LiteralSize, FieldRefSize, SizeExpr)):
            return val
        if isinstance(val, int):
            return LiteralSize(value=val)
        # field_ref returns a list of path segments
        if isinstance(val, list):
            return FieldRefSize(field_path=val)
        return FieldRefSize(field_path=[str(val)])

    def size_spec(self, items):
        if len(items) == 0:
            return None
        return items[0]

    # Size expression handlers
    def size_add(self, items):
        left, right = self._to_size_spec(items[0]), self._to_size_spec(items[1])
        return SizeExpr(op='+', left=left, right=right)

    def size_sub(self, items):
        left, right = self._to_size_spec(items[0]), self._to_size_spec(items[1])
        return SizeExpr(op='-', left=left, right=right)

    def size_mul(self, items):
        left, right = self._to_size_spec(items[0]), self._to_size_spec(items[1])
        return SizeExpr(op='*', left=left, right=right)

    def _to_size_spec(self, val):
        """Convert a value to a SizeSpec."""
        if isinstance(val, (LiteralSize, FieldRefSize, SizeExpr)):
            return val
        if isinstance(val, int):
            return LiteralSize(value=val)
        # field_ref returns a list of path segments
        if isinstance(val, list):
            return FieldRefSize(field_path=val)
        return FieldRefSize(field_path=[str(val)])

    # === Values ===

    def enum_value(self, items):
        enum_name, member_name = items
        return EnumValue(enum_name=enum_name, member_name=member_name)

    def value_expr(self, items):
        return items[0]

    def default_value(self, items):
        return items[0]

    # === Attributes ===

    def display_format(self, items):
        # items[0] is already a string from IDENT
        return DisplayFormat(name=str(items[0]))

    def attribute(self, items):
        if len(items) == 1:
            # doc attribute
            if isinstance(items[0], str):
                return ("doc", items[0])
            # display attribute
            return ("display", items[0])
        return items

    def attributes(self, items):
        attrs = FieldAttributes()
        for item in items:
            if isinstance(item, tuple):
                key, val = item
                if key == "display":
                    attrs.display = val
                elif key == "doc":
                    attrs.doc = val
        return attrs

    # === Match ===

    def match_pattern(self, items):
        if len(items) == 0:
            return None  # default case
        val = items[0]
        if isinstance(val, Token) and str(val) == "_":
            return None
        return val

    def match_branch(self, items):
        pattern = items[0]
        fields = items[1] if len(items) > 1 else []
        return MatchBranch(pattern=pattern, fields=fields)

    def match_branches(self, items):
        return list(items)

    def match_clause(self, items):
        # discriminator is a field_ref (list of path segments)
        discriminator = items[0]
        if isinstance(discriminator, list):
            discriminator = ".".join(discriminator)
        branches = items[1]
        return MatchClause(discriminator=discriminator, branches=branches)

    # === Fields ===

    def int_field(self, items):
        """Handle integer field: u8/u16/... field_name ..."""
        int_type = items[0]  # from integer_type
        idx = 1
        endian = None
        if idx < len(items) and isinstance(items[idx], Endianness):
            endian = items[idx]
            idx += 1

        name = items[idx]
        idx += 1

        default = None
        match = None
        attrs = None
        for item in items[idx:]:
            if isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        return Field(
            name=name,
            type=IntegerType(base=int_type, endian=endian),
            size=None,
            default_value=default,
            match_clause=match,
            attributes=attrs,
        )

    def bytes_field(self, items):
        """Handle bytes field: bytes field_name[size] ..."""
        # items[0] is "bytes" keyword (already processed)
        name = items[1]
        idx = 2

        size = None
        default = None
        match = None
        attrs = None

        for item in items[idx:]:
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        return Field(
            name=name,
            type=BytesType(),
            size=size,
            default_value=default,
            match_clause=match,
            attributes=attrs,
        )

    def string_field(self, items):
        """Handle string field: string[:cstr] field_name[size] ..."""
        # items[0] is "string" keyword
        idx = 1
        is_cstr = False
        if idx < len(items) and items[idx] == "cstr":
            is_cstr = True
            idx += 1

        name = items[idx]
        idx += 1

        size = None
        default = None
        match = None
        attrs = None

        for item in items[idx:]:
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        return Field(
            name=name,
            type=StringType(is_cstr=is_cstr),
            size=size,
            default_value=default,
            match_clause=match,
            attributes=attrs,
        )

    def pad_field(self, items):
        """Handle pad field: pad[size] = value"""
        # items[0] is "pad" keyword
        idx = 1

        size = None
        default = None
        attrs = None

        for item in items[idx:]:
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                size = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        return Field(
            name="_pad",  # Anonymous padding
            type=PadType(),
            size=size,
            default_value=default,
            attributes=attrs,
        )

    def BIT_KW(self, token):
        return "bit"

    def BITS_KW(self, token):
        return "bits"

    def bitfield_member(self, items):
        """Handle bit field member: bit name or bits[N] name"""
        if items[0] == "bit":
            # Single bit: bit name
            return BitField(name=items[1], bit_count=1)
        else:
            # Multiple bits: bits[N] name
            # items = ["bits", N, name]
            return BitField(name=items[2], bit_count=items[1])

    def bitfield_body(self, items):
        """Handle bitfield body: { bit_members... }"""
        return BitFieldBody(fields=list(items))

    def bitfield(self, items):
        """Handle bitfield: bits[N] field_name { ... }"""
        # items[0] is BitFieldType (with bit_count from parsing)
        bitfield_type = items[0]
        name = items[1]
        idx = 2

        body = None
        attrs = None

        for item in items[idx:]:
            if isinstance(item, BitFieldBody):
                body = item
            elif isinstance(item, FieldAttributes):
                attrs = item

        return Field(
            name=name,
            type=bitfield_type,
            bitfield_body=body,
            attributes=attrs,
        )

    def typed_field(self, items):
        """Handle field with type reference: TypeName field_name ..."""
        type_name = items[0]  # IDENT for type
        field_name = items[1]  # IDENT for field

        size = None
        default = None
        match = None
        attrs = None

        for item in items[2:]:
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, SizeExpr)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        return Field(
            name=field_name,
            type=EnumTypeRef(enum_name=type_name),
            size=size,
            default_value=default,
            match_clause=match,
            attributes=attrs,
        )

    # === Overrides ===

    def field_path(self, items):
        return list(items)

    def override_def(self, items):
        path = items[0]
        if len(items) == 2:
            second = items[1]
            if isinstance(second, list):
                # Structure override
                return StructureOverride(path=path, fields=second)
            else:
                # Value override
                return ValueOverride(path=path, value=second)
        return None

    # === Message ===

    def extends_clause(self, items):
        return items[0]

    def message_body(self, items):
        return list(items)

    def message_def(self, items):
        name = items[0]
        parent = None
        body = []

        for item in items[1:]:
            if isinstance(item, str):
                parent = item
            elif isinstance(item, list):
                body = item

        fields = [f for f in body if isinstance(f, Field)]
        overrides = [o for o in body if isinstance(o, (ValueOverride, StructureOverride))]

        return Message(
            name=name,
            parent=parent,
            fields=fields,
            overrides=overrides,
        )

    # === Definitions ===

    def definition(self, items):
        return items[0]

    def definitions(self, items):
        return list(items)

    # === Start ===

    def start(self, items):
        header = items[0]
        definitions = items[1] if len(items) > 1 else []

        constants = [d for d in definitions if isinstance(d, Constant)]
        enums = [d for d in definitions if isinstance(d, EnumDef)]
        messages = [d for d in definitions if isinstance(d, Message)]

        return CocoFile(
            version=header.get("version", "1.0"),
            endian=header.get("endian", Endianness.LITTLE),
            constants=constants,
            enums=enums,
            messages=messages,
        )


# Global parser instance
_parser = None


class ParseError(Exception):
    """Exception raised for parsing errors with line/column info."""
    def __init__(self, message: str, line: int = None, column: int = None, file_path: str = None):
        self.line = line
        self.column = column
        self.file_path = file_path
        super().__init__(message)

    def __str__(self):
        location = ""
        if self.file_path:
            location = f"{self.file_path}:"
        if self.line is not None:
            location += f"{self.line}:"
            if self.column is not None:
                location += f"{self.column}:"
        if location:
            return f"{location} {self.args[0]}"
        return self.args[0]


def parse(file_path: str | Path) -> CocoFile:
    """Parse a .coco file and return the AST."""
    from lark.exceptions import UnexpectedToken, UnexpectedCharacters, UnexpectedInput

    global _parser
    if _parser is None:
        _parser = get_parser()

    with open(file_path) as f:
        content = f.read()

    try:
        tree = _parser.parse(content)
    except UnexpectedToken as e:
        msg = f"Unexpected token '{e.token}'"
        if e.expected:
            expected = ", ".join(sorted(e.expected)[:5])
            msg += f". Expected one of: {expected}"
        raise ParseError(msg, line=e.line, column=e.column, file_path=str(file_path)) from None
    except UnexpectedCharacters as e:
        msg = f"Unexpected character '{content[e.pos_in_stream] if e.pos_in_stream < len(content) else 'EOF'}'"
        if e.allowed:
            allowed = ", ".join(sorted(e.allowed)[:5])
            msg += f". Expected one of: {allowed}"
        raise ParseError(msg, line=e.line, column=e.column, file_path=str(file_path)) from None
    except UnexpectedInput as e:
        raise ParseError(str(e), file_path=str(file_path)) from None

    transformer = CocoTransformer()
    return transformer.transform(tree)


def parse_string(content: str) -> CocoFile:
    """Parse a .coco string and return the AST."""
    global _parser
    if _parser is None:
        _parser = get_parser()

    tree = _parser.parse(content)
    transformer = CocoTransformer()
    return transformer.transform(tree)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python parser.py <file.coco>")
        sys.exit(1)

    result = parse(sys.argv[1])
    print(result)
