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
    LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize,
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

    # === Helper Methods ===

    def _validate_and_normalize_size(self, size, match_clause, field_name):
        """Validate size specification and convert VariableSize to BranchDeterminedSize when needed.

        Args:
            size: The size specification (VariableSize, GreedySize, etc.)
            match_clause: The match clause (if any)
            field_name: Field name for error messages

        Returns:
            Normalized size (converts VariableSize to BranchDeterminedSize if used with match)

        Raises:
            ValueError: If bare [] is used without match clause
        """
        if isinstance(size, VariableSize):
            if match_clause is None:
                raise ValueError(
                    f"Field '{field_name}': Bare [] requires a match clause. "
                    f"Use [...] for greedy matching or add a match clause."
                )
            # Convert VariableSize to BranchDeterminedSize when used with match
            return BranchDeterminedSize()
        return size

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

    # === Includes ===

    def include_decl(self, items):
        """Handle include: include "path" """
        return items[0]  # items[0] is the path string (already unquoted by STRING transformer)

    def include_section(self, items):
        """Collect all include declarations."""
        return list(items)

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
                if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                    size = item
            return (BytesType(), size)

        # string with optional encoding and size
        if first == "string":
            is_cstr = False
            size = None
            for item in items[1:]:
                if item == "cstr":
                    is_cstr = True
                elif isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                    size = item
            return (StringType(is_cstr=is_cstr), size)

        # pad with size
        if first == "pad":
            size = None
            for item in items[1:]:
                if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
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
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        # Validate and normalize size
        size = self._validate_and_normalize_size(size, match, field_name)

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

    def fill_to_size(self, items):
        """Transform fill_to: N into FillToSize(target_size=N)"""
        target_size = int(items[0])
        return FillToSize(target_size=target_size)

    def until_size(self, items):
        """Transform until: value into UntilSize(terminator=value)"""
        terminator_value = items[0]  # This is a parsed value_expr
        return UntilSize(terminator=terminator_value)

    def size_value(self, items):
        if len(items) == 0:
            return VariableSize()
        val = items[0]
        # Handle greedy size: [...] (GREEDY_SIZE token)
        if isinstance(val, Token) and (val.type == 'GREEDY_SIZE' or str(val) == "..."):
            return GreedySize()
        # Handle fill_to size (already transformed by fill_to_size method)
        if isinstance(val, FillToSize):
            return val
        # Handle until size (already transformed by until_size method)
        if isinstance(val, UntilSize):
            return val
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

    def match_body(self, items):
        """Handle match body: either braced message_body or single field_def."""
        if len(items) == 0:
            return []
        body = items[0]
        # If it's a single Field (shorthand), wrap in list
        if isinstance(body, Field):
            return [body]
        # Otherwise it's already a list from message_body
        return body if body else []

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
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        # Validate and normalize size
        size = self._validate_and_normalize_size(size, match, name)

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
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        # Validate and normalize size
        size = self._validate_and_normalize_size(size, match, name)

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
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                size = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        # Validate and normalize size (pad fields don't have match clauses)
        size = self._validate_and_normalize_size(size, None, "_pad")

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
            if isinstance(item, (LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize)):
                size = item
            elif isinstance(item, MatchClause):
                match = item
            elif isinstance(item, FieldAttributes):
                attrs = item
            elif item is not None:
                default = item

        # Validate and normalize size
        size = self._validate_and_normalize_size(size, match, field_name)

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
        # Check for optional 'layer' modifier
        is_layer = False
        idx = 0
        if isinstance(items[0], Token) and str(items[0]) == "layer":
            is_layer = True
            idx = 1

        name = items[idx]
        parent = None
        body = []

        for item in items[idx + 1:]:
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
            is_layer=is_layer,
        )

    # === Definitions ===

    def definition(self, items):
        return items[0]

    def definitions(self, items):
        return list(items)

    # === Start ===

    def start(self, items):
        header = items[0]

        # Check if include_section is present
        includes = []
        definitions_idx = 1
        if len(items) > 1 and isinstance(items[1], list) and all(isinstance(i, str) for i in items[1]):
            includes = items[1]
            definitions_idx = 2

        definitions = items[definitions_idx] if len(items) > definitions_idx else []

        constants = [d for d in definitions if isinstance(d, Constant)]
        enums = [d for d in definitions if isinstance(d, EnumDef)]
        messages = [d for d in definitions if isinstance(d, Message)]

        return CocoFile(
            version=header.get("version", "1.0"),
            endian=header.get("endian", Endianness.LITTLE),
            constants=constants,
            enums=enums,
            messages=messages,
            includes=includes,
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


def _resolve_fields_endianness(fields: list[Field], default_endian: Endianness) -> None:
    """Recursively resolve endianness for all IntegerType fields."""
    for field in fields:
        # Handle IntegerType
        if isinstance(field.type, IntegerType) and field.type.endian is None:
            field.type.endian = default_endian

        # Recurse into nested structures
        if field.structure_body:
            _resolve_fields_endianness(field.structure_body, default_endian)
        if field.match_clause:
            for branch in field.match_clause.branches:
                if branch.fields:
                    _resolve_fields_endianness(branch.fields, default_endian)
        # Bitfields don't have endianness issues, so no need to recurse into bitfield_body


def resolve_endianness(coco_file: CocoFile) -> None:
    """Bake file-level endian default into all fields with unspecified endianness.

    This is used when including files to preserve their endianness semantics
    even when merged into a file with a different default endianness.
    """
    for msg in coco_file.messages:
        _resolve_fields_endianness(msg.fields, coco_file.endian)


def merge_coco_files(main: CocoFile, included: list[CocoFile], main_path: Path) -> CocoFile:
    """Merge included files into main, silently skipping duplicate definitions.

    This handles diamond includes where the same definition appears multiple times
    through different include paths. Only truly conflicting definitions (same name,
    different content) would be an error, but we don't check for that currently.

    Args:
        main: The main CocoFile
        included: List of included CocoFiles (with their source paths already resolved)
        main_path: Path to main file (for error messages)

    Returns:
        Merged CocoFile with all definitions

    Raises:
        ParseError: Never raises for duplicates (silently skips)
    """
    all_constants = list(main.constants)
    all_enums = list(main.enums)
    all_messages = list(main.messages)

    # Track seen names to skip duplicates (diamond includes)
    seen_names = {
        'constants': {c.name for c in main.constants},
        'enums': {e.name for e in main.enums},
        'messages': {m.name for m in main.messages},
    }

    for inc in included:
        # Add constants (skip if already seen)
        for c in inc.constants:
            if c.name not in seen_names['constants']:
                seen_names['constants'].add(c.name)
                all_constants.append(c)

        # Add enums (skip if already seen)
        for e in inc.enums:
            if e.name not in seen_names['enums']:
                seen_names['enums'].add(e.name)
                all_enums.append(e)

        # Add messages (skip if already seen)
        for m in inc.messages:
            if m.name not in seen_names['messages']:
                seen_names['messages'].add(m.name)
                all_messages.append(m)

    return CocoFile(
        version=main.version,
        endian=main.endian,
        constants=all_constants,
        enums=all_enums,
        messages=all_messages,
        includes=[],  # Clear includes after merging
    )


def _parse_single_file(file_path: Path) -> CocoFile:
    """Parse a single .coco file without processing includes.

    Args:
        file_path: Path to the .coco file

    Returns:
        CocoFile with includes field populated but not processed

    Raises:
        ParseError: If parsing fails
    """
    from lark.exceptions import UnexpectedToken, UnexpectedCharacters, UnexpectedInput

    global _parser
    if _parser is None:
        _parser = get_parser()

    try:
        with open(file_path) as f:
            content = f.read()
    except FileNotFoundError:
        raise ParseError(f"Include file not found: {file_path}")

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


def _parse_with_includes(
    file_path: Path,
    visited: set[Path] | None = None,
    parsed_cache: dict[Path, CocoFile] | None = None
) -> CocoFile:
    """Parse a .coco file and recursively process includes.

    Args:
        file_path: Path to the .coco file
        visited: Set of files in current include chain (for circular detection)
        parsed_cache: Cache of already-parsed files (for diamond includes)

    Returns:
        CocoFile with all includes merged

    Raises:
        ParseError: If circular includes detected, file not found, or duplicate definitions
    """
    abs_path = file_path.resolve()

    if visited is None:
        visited = set()
    if parsed_cache is None:
        parsed_cache = {}

    # Check cache first (diamond include - same file via different paths)
    if abs_path in parsed_cache:
        return parsed_cache[abs_path]

    # Check for circular includes
    if abs_path in visited:
        chain = " -> ".join(str(p) for p in visited) + f" -> {abs_path}"
        raise ParseError(f"Circular include detected: {chain}", file_path=str(abs_path))

    visited.add(abs_path)

    # Parse this file
    coco_file = _parse_single_file(abs_path)

    # If no includes, cache and return
    if not coco_file.includes:
        parsed_cache[abs_path] = coco_file
        return coco_file

    # Process includes recursively
    included_files = []
    for inc_path in coco_file.includes:
        # Resolve path relative to the including file
        resolved_path = (abs_path.parent / inc_path).resolve()

        # Parse included file recursively (use visited.copy() for circular detection,
        # but share parsed_cache for diamond includes)
        inc_file = _parse_with_includes(resolved_path, visited.copy(), parsed_cache)

        # Bake in endianness to preserve semantics (only if not from cache)
        if resolved_path not in parsed_cache or parsed_cache[resolved_path] != inc_file:
            resolve_endianness(inc_file)

        included_files.append(inc_file)

    # Merge all files
    result = merge_coco_files(coco_file, included_files, abs_path)
    parsed_cache[abs_path] = result
    return result


def parse(file_path: str | Path) -> CocoFile:
    """Parse a .coco file and return the AST with includes resolved.

    Args:
        file_path: Path to the .coco file (str or Path)

    Returns:
        CocoFile with all includes merged and resolved

    Raises:
        ParseError: If parsing fails, circular includes detected, or duplicate definitions
    """
    return _parse_with_includes(Path(file_path))


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
