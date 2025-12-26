"""
AST Node definitions for Protococo DSL v1.0

These dataclasses represent the parsed structure of a .coco file.
"""

from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class Endianness(Enum):
    LITTLE = "le"
    BIG = "be"


@dataclass
class DisplayFormat:
    """Display format specifier - can be any formatter name."""
    name: str  # e.g., "hex", "ipv4", "mac", etc.


# === Constants ===

@dataclass
class Constant:
    """A named constant: const NAME = value"""
    name: str
    value: int | str  # int for numbers, str for strings


# === Enums ===

@dataclass
class EnumMember:
    """A single enum member: NAME = value"""
    name: str
    value: int


@dataclass
class EnumDef:
    """An enum definition: enum Name : base_type { members }"""
    name: str
    base_type: str  # e.g., "u8", "u16"
    members: list[EnumMember]

    def get_member_by_value(self, value: int) -> EnumMember | None:
        for m in self.members:
            if m.value == value:
                return m
        return None

    def get_member_by_name(self, name: str) -> EnumMember | None:
        for m in self.members:
            if m.name == name:
                return m
        return None


# === Field Types ===

@dataclass
class IntegerType:
    """Integer type: u8, u16, u32, u64, i8, i16, i32, i64"""
    base: str  # "u8", "u16", etc.
    endian: Endianness | None = None  # None means use file default

    @property
    def is_signed(self) -> bool:
        return self.base.startswith("i")

    @property
    def byte_size(self) -> int:
        sizes = {"8": 1, "16": 2, "32": 4, "64": 8}
        return sizes[self.base[1:]]


@dataclass
class BytesType:
    """bytes[N] or bytes[]"""
    pass


@dataclass
class StringType:
    """string[N], string:cstr[], or string[]"""
    is_cstr: bool = False  # True for null-terminated strings


@dataclass
class PadType:
    """pad[N] - padding bytes"""
    pass


@dataclass
class BitFieldType:
    """bits[N] { ... } - N is the total bit count (typically 8 or 16)"""
    bit_count: int = 8  # Default to 8 for backward compatibility


@dataclass
class EnumTypeRef:
    """Reference to an enum type by name"""
    enum_name: str


@dataclass
class MessageTypeRef:
    """Reference to a message type by name (for arrays/nesting)"""
    message_name: str


# Union of all field types
FieldType = IntegerType | BytesType | StringType | PadType | BitFieldType | EnumTypeRef | MessageTypeRef


# === Size Specifications ===

@dataclass
class LiteralSize:
    """Fixed size: [10]"""
    value: int


@dataclass
class FieldRefSize:
    """Size from another field: [length] or [header.total_length]"""
    field_path: list[str]  # ["length"] or ["header", "total_length"]

    @property
    def field_name(self) -> str:
        """For backward compatibility - returns the full dotted path."""
        return ".".join(self.field_path)


@dataclass
class VariableSize:
    """Variable size to end: []"""
    pass


@dataclass
class GreedySize:
    """Greedy size [...] - consumes all remaining bytes from outer layer"""
    pass


@dataclass
class SizeExpr:
    """Arithmetic size expression: [length - 8], [count * 4]"""
    op: str  # '+', '-', '*'
    left: 'SizeSpec'
    right: 'SizeSpec'


@dataclass
class FillToSize:
    """Fill to minimum size: [fill_to: N]

    Consumes bytes until the total message size reaches N bytes.
    Used for protocols with minimum frame/message sizes (e.g., Ethernet 60-byte minimum).
    """
    target_size: int


@dataclass
class UntilSize:
    """Terminator-based size: [until: value]

    Reads bytes until a specific terminator value is encountered (inclusive).
    The terminator byte is included in the field.
    Used for null-terminated strings, DNS label sequences, etc.

    Examples:
        bytes qname[until: 0x00]  # Read until null byte (inclusive)
        bytes label[until: 0xFF]  # Read until 0xFF marker
    """
    terminator: 'Value'


@dataclass
class BranchDeterminedSize:
    """Size determined by matched branch: [*]

    Used with match clauses where different branches have different sizes.
    The parser will decode the match branch and use consumed bytes as size.
    """
    pass


SizeSpec = LiteralSize | FieldRefSize | VariableSize | GreedySize | SizeExpr | FillToSize | UntilSize | BranchDeterminedSize | None


# === Values ===

@dataclass
class EnumValue:
    """Reference to enum member: EnumName.MEMBER"""
    enum_name: str
    member_name: str


# === Attributes ===

@dataclass
class FieldAttributes:
    """Field metadata: [display: hex, doc: "description"]"""
    display: DisplayFormat | None = None
    doc: str | None = None


# === Match Branches ===

@dataclass
class MatchBranch:
    """A single match branch: pattern -> { fields }"""
    pattern: int | EnumValue | None  # None = default (_)
    fields: list["Field"]


@dataclass
class MatchClause:
    """Pattern matching: match discriminator { branches }"""
    discriminator: str  # field name to match on
    branches: list[MatchBranch]


# === Bit Fields ===

@dataclass
class BitField:
    """A single bit field within bits[8]: bit flag or bits[3] mode"""
    name: str
    bit_count: int  # 1 for 'bit', N for 'bits[N]'


@dataclass
class BitFieldBody:
    """Body of a bits[8] field"""
    fields: list[BitField]


# === Fields ===

@dataclass
class Field:
    """A field definition within a message"""
    name: str
    type: FieldType
    size: SizeSpec = None
    default_value: int | str | EnumValue | None = None
    match_clause: MatchClause | None = None
    attributes: FieldAttributes | None = None
    bitfield_body: BitFieldBody | None = None  # For bits[8] fields
    structure_body: list["Field"] | None = None  # For bytes with inline structure


# === Overrides ===

@dataclass
class ValueOverride:
    """Override a field's value: field_path = value"""
    path: list[str]  # e.g., ["body", "content", "cmd"]
    value: int | str | EnumValue


@dataclass
class StructureOverride:
    """Override a bytes field with structure: field_path { fields }"""
    path: list[str]
    fields: list[Field]


Override = ValueOverride | StructureOverride


# === Messages ===

@dataclass
class Message:
    """A message definition"""
    name: str
    parent: str | None = None  # Name of parent message if extends
    fields: list[Field] = field(default_factory=list)
    overrides: list[Override] = field(default_factory=list)
    is_layer: bool = False  # True if this message represents a protocol layer


# === File ===

@dataclass
class CocoFile:
    """Root AST node representing a complete .coco file"""
    version: str
    endian: Endianness
    constants: list[Constant] = field(default_factory=list)
    enums: list[EnumDef] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)  # Temporary: used during parsing, cleared after merge

    def get_constant(self, name: str) -> Constant | None:
        for c in self.constants:
            if c.name == name:
                return c
        return None

    def get_enum(self, name: str) -> EnumDef | None:
        for e in self.enums:
            if e.name == name:
                return e
        return None

    def get_message(self, name: str) -> Message | None:
        for m in self.messages:
            if m.name == name:
                return m
        return None

    def get_subtypes(self, name: str) -> list[Message]:
        """Get all messages that directly or indirectly extend the given message."""
        subtypes = []
        for m in self.messages:
            if self._is_subtype_of(m, name):
                subtypes.append(m)
        return subtypes

    def _is_subtype_of(self, msg: Message, ancestor_name: str) -> bool:
        """Check if msg is a subtype of ancestor_name."""
        if msg.parent is None:
            return False
        if msg.parent == ancestor_name:
            return True
        parent = self.get_message(msg.parent)
        if parent:
            return self._is_subtype_of(parent, ancestor_name)
        return False
