#!/usr/bin/env python3
"""protococo.

Usage:
  protococo check  <message_name> [<message_hex_string> ...]
                      [--cocofile=<file> --format=<option>]
                      [--dissect-fields=<comma_separated_fields>]
                      [--verbose --decode --decode-no-newlines --tree --layer-colors --follow-pointers]
                      [--layer=<name>]
                      [-L <n> | --field-bytes-limit=<n>]
  protococo find   [<message_hex_string> ...]
                      [--cocofile=<file> --format=<option>]
                      [--dissect | --dissect-fields=<comma_separated_fields>]
                      [--list --verbose --decode --decode-no-newlines --long-names --tree --layer-colors --follow-pointers]
                      [--layer=<name>]
                      [-L <n> | --field-bytes-limit=<n>]
  protococo create (<message_name> | --from-json=<json_file>)
                      [--cocofile=<file>]
  protococo json-recipe <message_names> ...
                      [--cocofile=<file>]
  protococo tree   [--cocofile=<file>]
  protococo mspec  <message_name> [--cocofile=<file>]
  protococo wireshark [<message_name>] [--cocofile=<file>] [--stack]

Options:
  -h --help                 Show this screen.
  --version                 Show version.
  --cocofile=<file>         Specify the protococo rules file [default: default.coco].
  --verbose                 Enable verbose output.
  --format=<option>         Print message disection in different formats [default: compact].
                                Options: oneline, multiline, compact, porcelain, json, tree.
                                porcelain: machine-readable space-padded columns, no colors.
                                json: structured JSON output.
                                tree: hierarchical tree structure with box-drawing chars.
  --dissect                 Include message field dissection in find results.
  --decode                  Decodes fields with encodedas parameters in message dissection
  --decode-no-newlines      Replaces new lines in decoded fields of message dissections with \'\\n\' for a more compact output
  --follow-pointers         Follow offset-based references (@) when decoding. Defaults to --decode value.
  --long-names              Prints the full mangled message names if a name mangling preprocess has been made during cocofile parsing
  --list                    Include a list of the most fitting messages in find results.
  --tree                    Display dissected fields as a tree structure.
  --layer-colors            Color tree background by protocol layer depth (requires --tree).
  --layer=<name>            Filter output to show only the specified protocol layer subtree.
  -L <n>, --field-bytes-limit=<n>
                            Truncate long field values to N bytes in output [default: 32].
                                Use 0 for unlimited.

"""

__version__ = "0.3.0"

from pprint import *
from collections import OrderedDict
from typing import Any
import re
import os
import sys
import json
import copy
from docopt import docopt
from parser import parse, ParseError
from analyzer import Decoder, ValidationResult, DecodeResult, FieldValue, extract_layer_subtree
from encoder import Encoder
from coco_ast import EnumTypeRef, BranchDeterminedSize
import formatters


def truncate_field_value(value: str, limit_bytes: int) -> str:
    """Truncate a hex string or text value to the given byte limit.

    Args:
        value: Hex string or text value
        limit_bytes: Maximum bytes to show (0 = unlimited)

    Returns:
        Truncated value with "+N" suffix showing omitted bytes
    """
    if limit_bytes <= 0 or not value:
        return value

    # Check if it's a hex string (all hex chars)
    is_hex = all(c in '0123456789abcdefABCDEF' for c in value)

    if is_hex:
        # Hex string: 2 chars per byte
        total_bytes = len(value) // 2
        if total_bytes <= limit_bytes:
            return value
        truncated = value[:limit_bytes * 2]
        omitted = total_bytes - limit_bytes
        return f"{truncated}...+{omitted}B"
    else:
        # Text string: 1 char per byte (approximately)
        total_bytes = len(value)
        if total_bytes <= limit_bytes:
            return value
        truncated = value[:limit_bytes]
        omitted = total_bytes - limit_bytes
        return f"{truncated}...+{omitted}B"


def collect_field_metadata(decoder: Decoder, msg, prefix: str = "", visited_counts: dict = None) -> dict:
    """Recursively collect field metadata including from embedded messages.

    Args:
        decoder: Decoder instance
        msg: Message definition
        prefix: Path prefix for nested fields
        visited_counts: Dict mapping message names to visit counts (for recursion control)

    Returns:
        Dict mapping field paths to Field objects
    """
    if visited_counts is None:
        visited_counts = {}
        
    # Allow a small amount of recursion for types like dns_name
    count = visited_counts.get(msg.name, 0)
    if count >= 3: # Allow up to 3 levels of same-type nesting
        return {}
        
    new_visited = dict(visited_counts)
    new_visited[msg.name] = count + 1
    
    metadata = {}
    fields = decoder.resolve_message(msg)

    def collect_from_fields(fields_list: list, field_prefix: str, current_visited: dict):
        """Helper to collect metadata from a list of fields."""
        for field in fields_list:
            # Check if this field should be flattened (BranchDeterminedSize [], anonymous _, or has match)
            from coco_ast import BranchDeterminedSize
            is_flattened = (isinstance(field.size, BranchDeterminedSize) or 
                            field.name == "_" or 
                            field.match_clause is not None)
            
            field_key = f"{field_prefix}{field.name}" if field_prefix else field.name
            
            # If not anonymous, register this field
            if field.name != "_":
                metadata[field_key] = field

            # If flattened, children use the same prefix as this field
            # Otherwise, children use this field's name as prefix
            if is_flattened:
                nested_prefix = field_prefix
            else:
                nested_prefix = f"{field_key}."

            # Check for embedded message
            if isinstance(field.type, EnumTypeRef):
                embedded_msg = decoder.coco_file.get_message(field.type.enum_name)
                if embedded_msg:
                    # Recursively collect from embedded message
                    if field.structure_body:
                        # Use overridden structure
                        collect_from_fields(field.structure_body, nested_prefix, current_visited)
                    else:
                        # Use original message fields
                        nested = collect_field_metadata(decoder, embedded_msg, nested_prefix, current_visited)
                        metadata.update(nested)

            # Check for structure body (structure override on bytes field)
            if field.structure_body and not isinstance(field.type, EnumTypeRef):
                collect_from_fields(field.structure_body, nested_prefix, current_visited)

            # Check for match clause - traverse all branches
            if field.match_clause:
                for branch in field.match_clause.branches:
                    if branch.fields:
                        collect_from_fields(branch.fields, nested_prefix, current_visited)

    collect_from_fields(fields, prefix, new_visited)
    return metadata


class AnsiColors:
    PURPLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKCYAN = '\033[96m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    FAIL2 = '\033[38;5;196m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    UNDERLINE_OFF = '\033[24m'
    # Background colors for layer visualization (256-color mode, dark subtle tones)
    LAYER_BG = [
        '\033[48;5;238m',  # Layer 0: medium dark gray (visible on black)
        '\033[48;5;17m',   # Layer 1: dark blue
        '\033[48;5;52m',   # Layer 2: dark red
        '\033[48;5;22m',   # Layer 3: dark green
        '\033[48;5;53m',   # Layer 4: dark purple
        '\033[48;5;23m',   # Layer 5: dark cyan
    ]
    BG_RESET = '\033[49m'


def field_matches_filter(field_name: str, field_path: str, filter_fields: list) -> bool:
    """Check if a field matches any of the filter patterns.

    Args:
        field_name: Simple field name (e.g., "protocol")
        field_path: Full dotted path (e.g., "header.protocol")
        filter_fields: List of filter patterns (simple names or dotted paths)

    Returns:
        True if the field matches any filter pattern
    """
    if filter_fields is None:
        return True

    # Use field_path if available, otherwise field_name
    effective_path = field_path if field_path else field_name

    for pattern in filter_fields:
        # Exact match on simple name
        if field_name == pattern:
            return True
        # Exact match on full path
        if effective_path == pattern:
            return True
        # Pattern is a dotted path - check if field_path ends with it
        if '.' in pattern:
            if effective_path == pattern or effective_path.endswith('.' + pattern):
                return True
            # Field is a prefix of the pattern (e.g., "content" matches "content.text")
            if pattern.startswith(field_name + '.') or pattern.startswith(effective_path + '.'):
                return True

    return False


def validation_result_to_tuple(result: ValidationResult, fields_metadata: dict = None, coco_file = None, decode: bool = False):
    """Convert new ValidationResult to old 5-tuple format for display functions.

    Old format:
    - [0] is_valid (bool)
    - [1] validation_result_dict (OrderedDict field_name -> hex_value)
    - [2] validation_diff_dict (dict field_name -> bool compliance)
    - [3] validation_log_dict (dict field_name -> list of error messages)
    - [4] validation_decoded_dict (dict field_name -> decoded value string)
    """
    validation_result_dict = OrderedDict()
    validation_diff_dict = {}
    validation_log_dict = {}
    validation_decoded_dict = {}

    # Track field name occurrences to make duplicates unique
    name_counts = {}

    def extract_val(v):
        """Extract the decoded value from FieldValue or return as-is."""
        if isinstance(v, FieldValue):
            return v.val
        return v

    def dict_to_plain(d: dict, parent_path: str = "") -> dict:
        """Convert a dict with FieldValue objects to a plain dict with just values, formatted for display."""
        result = {}
        for k, v in d.items():
            field_path = f"{parent_path}.{k}" if parent_path else k
            # Strip array indices from field_path for metadata lookup
            # e.g., "questions[0].qname" -> "questions.qname"
            field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
            actual_val = extract_val(v)
            hex_val = v.hex if isinstance(v, FieldValue) else ""
            
            # Check if this field is flattened (BranchDeterminedSize [])
            metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path) or fields_metadata.get(k)
            is_flattened = isinstance(getattr(metadata, 'size', None), BranchDeterminedSize)

            # Check if this structured field has a display formatter
            if decode and metadata:
                if metadata.attributes and metadata.attributes.display:
                    fmt_name = metadata.attributes.display.name
                    formatted = formatters.format_value(fmt_name, hex_val, decoded_value=actual_val)
                    if formatted:
                        result[k] = formatted
                        continue

            if isinstance(actual_val, dict):
                # If flattened, children use the same prefix as this field's parent
                child_parent_path = parent_path if is_flattened else field_path
                result[k] = dict_to_plain(actual_val, child_parent_path)
            elif isinstance(actual_val, list):
                result[k] = [
                    dict_to_plain(extract_val(item), f"{field_path}[{i}]") if isinstance(extract_val(item), dict)
                    else format_val(f"{field_path}[{i}]", extract_val(item).hex if isinstance(extract_val(item), FieldValue) else "", extract_val(item))
                    for i, item in enumerate(actual_val)
                ]
            else:
                result[k] = format_val(field_path, hex_val, actual_val)
        return result

    def format_val(field_path: str, hex_val: str, decoded_val: Any) -> str:
        """Format a value using display formatters and enum lookups."""
        if not decode:
            return str(hex_val)
        
        # Try display formatter from metadata
        if fields_metadata:
            # Strip array indices from field_path for metadata lookup
            field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
            metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path)
            if metadata and metadata.attributes and metadata.attributes.display:
                fmt_name = metadata.attributes.display.name
                formatted = formatters.format_value(fmt_name, hex_val, decoded_value=decoded_val)
                if formatted:
                    return formatted
        
        # Try enum formatting
        if coco_file and isinstance(decoded_val, str) and "." in decoded_val and not decoded_val.startswith("0x"):
            parts = decoded_val.split(".", 1)
            if len(parts) == 2:
                enum_name, member_name = parts
                enum_def = coco_file.get_enum(enum_name)
                if enum_def:
                    member = enum_def.get_member_by_name(member_name)
                    if member:
                        return f"{member.value} ({decoded_val})"
        
        # Return raw decoded value as string
        return str(decoded_val)

    def flatten_to_decoded(d: dict, parent_path: str):
        """Recursively flatten nested dict into validation_decoded_dict for filtering."""
        for k, v in d.items():
            field_path = f"{parent_path}.{k}"
            # Extract value from FieldValue if present
            actual_val = extract_val(v)
            hex_val = v.hex if isinstance(v, FieldValue) else ""
            
            # Check if this structured field has a display formatter
            if decode and fields_metadata:
                # Strip array indices from field_path for metadata lookup
                field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
                metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path)
                if metadata and metadata.attributes and metadata.attributes.display:
                    fmt_name = metadata.attributes.display.name
                    formatted = formatters.format_value(fmt_name, hex_val, decoded_value=actual_val)
                    if formatted:
                        validation_decoded_dict[field_path] = formatted
                        continue

            if isinstance(actual_val, dict):
                flatten_to_decoded(actual_val, field_path)
            elif isinstance(actual_val, list):
                # Convert list items, extracting from FieldValue
                converted_list = [extract_val(item) for item in actual_val]
                validation_decoded_dict[field_path] = str(converted_list)
            else:
                validation_decoded_dict[field_path] = format_val(field_path, hex_val, actual_val)

    for field in result.fields:
        # Make field names unique if they appear multiple times
        base_name = field.name
        if base_name in name_counts:
            name_counts[base_name] += 1
            unique_name = f"{base_name}_{name_counts[base_name]}"
        else:
            name_counts[base_name] = 0
            unique_name = base_name

        validation_result_dict[unique_name] = field.hex_value
        validation_diff_dict[unique_name] = field.is_valid

        if field.errors:
            validation_log_dict[unique_name] = field.errors

        # Check if this field is flattened (BranchDeterminedSize [])
        metadata = fields_metadata.get(field.name) if fields_metadata else None
        is_flattened = isinstance(getattr(metadata, 'size', None), BranchDeterminedSize)

        if field.decoded_value is not None:
            if isinstance(field.decoded_value, dict):
                # If flattened, children use the same prefix as this field's parent (empty here)
                child_parent_path = "" if is_flattened else unique_name
                # Flatten nested structure for path-based filtering
                flatten_to_decoded(field.decoded_value, child_parent_path)
                # Convert to plain dict (without FieldValue wrappers) for string representation
                validation_decoded_dict[unique_name] = str(dict_to_plain(field.decoded_value, child_parent_path))
            elif isinstance(field.decoded_value, str):
                validation_decoded_dict[unique_name] = format_val(unique_name, field.hex_value, field.decoded_value)
            else:
                validation_decoded_dict[unique_name] = format_val(unique_name, field.hex_value, field.decoded_value)

    # Add remaining bytes as overflow field if present
    if result.remaining_bytes:
        validation_result_dict[None] = result.remaining_bytes
        validation_diff_dict[None] = False

    return (
        result.is_valid,
        validation_result_dict,
        validation_diff_dict,
        validation_log_dict,
        validation_decoded_dict
    )
    
def get_message_explanation_string_compact(validation_result, filter_fields = None, decode=False, no_newlines=False, field_bytes_limit: int = 32):
    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result

    result_string = ""
    odd = 0
    for k, v in validation_result_dict.items():
        # Use path-based filtering - k is the field path (e.g., "header.protocol")
        field_name = k.split('.')[-1] if k and '.' in k else k
        if not field_matches_filter(field_name, k, filter_fields):
            continue

        odd ^= 1

        field_complies = validation_diff_dict[k]

        k_adj, v_adj = k, v
        is_decoded = decode == True and k in validation_decoded_dict.keys()

        if is_decoded:
            v_adj = validation_decoded_dict[k]

        # Apply field bytes limit truncation
        # Only truncate hex values or long decoded strings, not structured or short formatted ones
        if field_bytes_limit > 0:
            if not is_decoded:
                v_adj = truncate_field_value(v_adj, field_bytes_limit)
            elif isinstance(v_adj, str) and not v_adj.startswith('{') and not v_adj.startswith('[') and len(v_adj) > 256:
                v_adj = truncate_field_value(v_adj, field_bytes_limit)

        v_display = str(v_adj)
        fail_color = AnsiColors.FAIL if odd == 1 else AnsiColors.FAIL2
        ok_color = AnsiColors.OKGREEN if odd == 1 else AnsiColors.OKCYAN
        if not field_complies:
            color = fail_color
        else:
            color = ok_color

        v_display = AnsiColors.BOLD + color + v_display + AnsiColors.ENDC

        if decode == True and k in validation_decoded_dict.keys():
            if no_newlines:
                v_display = f"({v_display})".replace("\r", "").replace("\n", f"{AnsiColors.PURPLE}\\n{AnsiColors.UNDERLINE_OFF + AnsiColors.BOLD + color}")
            else:
                v_display = f"({v_display})"

        if k_adj is not None:
            result_string += f"{v_display}"
        else:   # Overflowing bytes field
            result_string += f"|+{v_display}"



    return result_string

def get_message_explanation_string_oneline(validation_result, filter_fields = None, decode=False, no_newlines=False, field_bytes_limit: int = 32):

    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result

    fail_color = AnsiColors.FAIL
    ok_color = AnsiColors.OKGREEN

    result_string = ""
    for k, v in validation_result_dict.items():
        # Use path-based filtering - k is the field path (e.g., "header.protocol")
        field_name = k.split('.')[-1] if k and '.' in k else k
        if not field_matches_filter(field_name, k, filter_fields):
            continue

        field_complies = validation_diff_dict[k]

        k_adj, v_adj = k, v
        is_decoded = decode == True and k in validation_decoded_dict.keys()

        if is_decoded:
            v_adj = validation_decoded_dict[k]

        # Apply field bytes limit truncation
        # Only truncate hex values or long decoded strings, not structured or short formatted ones
        if field_bytes_limit > 0:
            if not is_decoded:
                v_adj = truncate_field_value(v_adj, field_bytes_limit)
            elif not v_adj.startswith('{') and not v_adj.startswith('[') and len(v_adj) > 256:
                v_adj = truncate_field_value(v_adj, field_bytes_limit)

        if not field_complies:
            color = fail_color
        else:
            color = ok_color

        v_adj = AnsiColors.BOLD + color + v_adj + AnsiColors.ENDC

        if decode == True and k in validation_decoded_dict.keys():
            if no_newlines:
                v_adj = f"({v_adj})".replace("\r", "").replace("\n", f"{AnsiColors.PURPLE}\\n{AnsiColors.UNDERLINE_OFF + AnsiColors.BOLD + color}")
            else:
                v_adj = f"({v_adj})"

        if k_adj is not None:
            k_adj = AnsiColors.BOLD + k_adj + AnsiColors.ENDC
            result_string += f"|{k_adj}: {v_adj}"
        else:   # Overflowing bytes field
            result_string += f"|+{v_adj}"

    if len(result_string) > 0:
        result_string += "|"

    return result_string

def get_message_explanation_string_multiline(validation_result, filter_fields = None, decode=False, no_newlines=False, field_bytes_limit: int = 32):

    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result

    fail_color = AnsiColors.FAIL
    ok_color = AnsiColors.OKGREEN

    result_string_field_names = ""
    result_string_field_values = ""
    for k, v in validation_result_dict.items():
        # Use path-based filtering - k is the field path (e.g., "header.protocol")
        field_name = k.split('.')[-1] if k and '.' in k else k
        if not field_matches_filter(field_name, k, filter_fields):
            continue

        field_complies = validation_diff_dict[k]

        k_adj, v_adj = k, v
        is_decoded = decode == True and k in validation_decoded_dict.keys()

        if is_decoded:
            v_adj = validation_decoded_dict[k]

        # Apply field bytes limit truncation
        # Only truncate hex values or long decoded strings, not structured or short formatted ones
        if field_bytes_limit > 0:
            if not is_decoded:
                v_adj = truncate_field_value(v_adj, field_bytes_limit)
            elif not v_adj.startswith('{') and not v_adj.startswith('[') and len(v_adj) > 256:
                v_adj = truncate_field_value(v_adj, field_bytes_limit)

        if k_adj is None:
            k_adj = "+"
            v_adj = "+" + v

        lendiff = len(k_adj) - len(v_adj)

        if decode == True and k in validation_decoded_dict.keys():
            lendiff-=2  #To compensate the fact that we are adding 2 parenthesis
            if no_newlines:
                v_adj = f"({v_adj})".replace("\r", "").replace("\n", f"{AnsiColors.PURPLE}\\n{AnsiColors.UNDERLINE_OFF + AnsiColors.BOLD + color}")
            else:
                v_adj = f"({v_adj})"

        if not field_complies:
            color = fail_color
        else:
            color = ok_color

        v_adj = AnsiColors.BOLD + color + v_adj + AnsiColors.ENDC
            
        if lendiff < 0:
            prefix = " " * ((-lendiff)//2)
            suffix = " " * ((-lendiff)//2 + (-lendiff)%2)
            k_adj = prefix + k_adj + suffix
            #k_adj += " " * (-lendiff)
        elif lendiff > 0:
            prefix = " " * (lendiff//2)
            suffix = " " * (lendiff//2 + (-lendiff)%2)
            v_adj = prefix + v_adj + suffix
            #v_adj += " " * lendiff
        k_adj = "|" + k_adj
        v_adj = "|" + v_adj
        
        result_string_field_names += k_adj
        result_string_field_values += v_adj
    
    if len(result_string_field_names) >0:
        result_string_field_names += "|"
        result_string_field_values += "|"
    
    return result_string_field_names + "\n" + result_string_field_values

def get_message_explanation_string_tree(validation_result: ValidationResult, fields_metadata: dict = None, decode=False, filter_fields=None, coco_file=None, field_bytes_limit: int = 32, protocol_chain: list = None, layer_colors: bool = False):
    """Format validation result as a tree structure.

    Args:
        validation_result: The ValidationResult object (not tuple)
        fields_metadata: Dict mapping field names to Field objects (for display attributes)
        decode: Whether to decode values using display formatters
        filter_fields: List of field names/paths to include (None = all fields)
        coco_file: CocoFile for looking up enum values (for "N (Enum.Member)" format)
        field_bytes_limit: Maximum bytes to show for field values (0 = unlimited)
        protocol_chain: List of layer field names for layer coloring (e.g., ["eth", "ip", "tcp"])
        layer_colors: Whether to apply background colors based on layer depth
    """
    lines = []
    layer_fields = set(protocol_chain) if protocol_chain else set()
    # Map layer field names to their position in the chain for consistent coloring
    layer_positions = {name: idx for idx, name in enumerate(protocol_chain)} if protocol_chain else {}

    def format_enum_display(value: str) -> str:
        """Format enum value as 'N (Enum.Member)' if possible."""
        if not decode or not coco_file or not isinstance(value, str):
            return value
        # Check if value looks like "EnumName.MemberName"
        if '.' in value and not value.startswith('0x'):
            parts = value.split('.', 1)
            if len(parts) == 2:
                enum_name, member_name = parts
                enum_def = coco_file.get_enum(enum_name)
                if enum_def:
                    member = enum_def.get_member_by_name(member_name)
                    if member:
                        return f"{member.value} ({value})"
        return value

    def has_matching_descendants(d: dict, parent_path: str) -> bool:
        """Check if any descendant field matches the filter."""
        if filter_fields is None:
            return True
        for k, v in d.items():
            field_path = f"{parent_path}.{k}" if parent_path else k
            # Extract actual value from FieldValue if present
            actual_val = v.val if isinstance(v, FieldValue) else v
            if field_matches_filter(k, field_path, filter_fields):
                return True
            if isinstance(actual_val, dict) and has_matching_descendants(actual_val, field_path):
                return True
            if isinstance(actual_val, list):
                for j, item in enumerate(actual_val):
                    if isinstance(item, dict) and has_matching_descendants(item, f"{field_path}[{j}]"):
                        return True
        return False

    def format_value(field_result: DecodeResult, metadata=None) -> str:
        """Format a single field's value."""
        hex_val = field_result.hex_value
        decoded = field_result.decoded_value

        # Show "(none)" for empty fields (0 bytes) when decoding
        if decode and (not hex_val or len(hex_val) == 0):
            return "(none)"

        # If decode=False, show hex values but still expand nested structures
        if not decode:
            # For nested structures, return None to trigger tree expansion
            if isinstance(decoded, dict):
                return None
            # For leaf nodes, return raw hex
            return truncate_field_value(hex_val, field_bytes_limit)

        # decode=True: apply formatters and use decoded value
        if metadata and metadata.attributes and metadata.attributes.display:
            fmt_name = metadata.attributes.display.name
            formatted = formatters.format_value(fmt_name, hex_val, decoded_value=decoded)
            if formatted:
                return formatted  # Formatted values (like IP addresses) are not truncated

        # Use decoded value if available
        if decoded is not None:
            if isinstance(decoded, dict):
                # Nested structure - will be handled recursively, UNLESS we already formatted it
                return None
            elif isinstance(decoded, str):
                # Check if it's an enum value (don't truncate) or raw hex/text (truncate)
                formatted = format_enum_display(decoded)
                if formatted != decoded:
                    # It was formatted as an enum, don't truncate
                    return formatted
                # Check if it looks like hex or plain text
                return truncate_field_value(decoded, field_bytes_limit)
            else:
                return str(decoded)

        return truncate_field_value(hex_val, field_bytes_limit)

    def build_prefix(ancestors: list[bool], layer_stack: list[int] = None) -> str:
        """Build prefix string from ancestor continuation flags.

        Args:
            ancestors: List of booleans, True if that ancestor level needs a continuation line (│)
            layer_stack: List of layer indices for each ancestor level (for coloring)
        """
        if layer_stack is None:
            layer_stack = []

        prefix = ""
        for i, needs_line in enumerate(ancestors):
            segment = "│   " if needs_line else "    "
            # Apply layer color if available for this level
            if layer_colors and i < len(layer_stack) and layer_stack[i] >= 0:
                bg_color = AnsiColors.LAYER_BG[layer_stack[i] % len(AnsiColors.LAYER_BG)]
                segment = f"{bg_color}{segment}{AnsiColors.BG_RESET}"
            prefix += segment
        return prefix

    def build_connector(connector: str, layer_idx: int) -> str:
        """Build a connector (├── or └──) with optional layer coloring."""
        if layer_colors and layer_idx >= 0:
            bg_color = AnsiColors.LAYER_BG[layer_idx % len(AnsiColors.LAYER_BG)]
            return f"{bg_color}{connector}{AnsiColors.BG_RESET}"
        return connector

    def format_line_content(content: str, layer_idx: int) -> str:
        """Wrap line content with layer background color if enabled."""
        if layer_colors and layer_idx >= 0:
            bg_color = AnsiColors.LAYER_BG[layer_idx % len(AnsiColors.LAYER_BG)]
            return f"{bg_color}{content}{AnsiColors.BG_RESET}"
        return content

    def get_effective_layer(layer_stack: list[int]) -> int:
        """Get the last valid (non-negative) layer index from the stack."""
        for idx in reversed(layer_stack):
            if idx >= 0:
                return idx
        return -1

    def add_field(field_result: DecodeResult, ancestors: list[bool] = None, metadata=None, is_last=False, parent_path: str = "", layer_stack: list[int] = None, current_layer_idx: int = -1):
        """Add a field to the tree."""
        if ancestors is None:
            ancestors = []
        if layer_stack is None:
            layer_stack = []

        name = field_result.name if field_result.name else "+"
        field_path = f"{parent_path}.{name}" if parent_path else name

        # Check if this field or any descendants match the filter
        self_matches = field_matches_filter(name, field_path, filter_fields)
        has_nested = isinstance(field_result.decoded_value, dict)
        descendants_match = has_nested and has_matching_descendants(field_result.decoded_value, field_path)

        if not self_matches and not descendants_match:
            return

        prefix = build_prefix(ancestors, layer_stack)
        connector_str = "└── " if is_last else "├── "
        connector = build_connector(connector_str, current_layer_idx)

        # Color based on validity
        if field_result.is_valid:
            color = AnsiColors.OKGREEN
        else:
            color = AnsiColors.FAIL

        # Determine background layer for this field's label and for sibling lines
        content_layer_idx = current_layer_idx

        # Check if this field is a layer field - use its position in the chain
        field_layer_idx = layer_positions.get(name, -1)

        # Determine layer for nested content
        # If this field IS a layer, nested content uses its layer color
        # Otherwise, nested content inherits current layer
        if field_layer_idx >= 0:
            nested_content_layer = field_layer_idx
        else:
            nested_content_layer = content_layer_idx

        # Check if this field uses branch-determined size [] and should be flattened
        from coco_ast import BranchDeterminedSize
        is_branch_determined = metadata and isinstance(getattr(metadata, 'size', None), BranchDeterminedSize)

        # If branch-determined and has nested content, flatten it at this level
        if is_branch_determined and has_nested:
            # Don't show this field name, just show its contents flattened
            # Pass is_last_sibling to indicate whether there are more fields after this one
            add_nested_dict(field_result.decoded_value, ancestors, parent_path, layer_stack, is_last_sibling=is_last, current_layer_idx=current_layer_idx)
            return

        # Handle arrays
        if isinstance(field_result.decoded_value, list):
            content = f"{AnsiColors.BOLD}{name}{AnsiColors.ENDC}: [{len(field_result.decoded_value)} items]"
            lines.append(f"{prefix}{connector}{format_line_content(content, content_layer_idx)}")
            list_ancestors = ancestors + [not is_last]
            new_layer_stack = layer_stack + [content_layer_idx]
            list_prefix = build_prefix(list_ancestors, new_layer_stack)
            for j, item in enumerate(field_result.decoded_value):
                item_is_last = (j == len(field_result.decoded_value) - 1)
                item_connector_str = "└── " if item_is_last else "├── "
                item_connector = build_connector(item_connector_str, nested_content_layer)
                if isinstance(item, dict):
                    item_content = f"[{j}]:"
                    lines.append(f"{list_prefix}{item_connector}{format_line_content(item_content, nested_content_layer)}")
                    item_ancestors = list_ancestors + [not item_is_last]
                    item_layer_stack = new_layer_stack + [nested_content_layer]
                    add_nested_dict(item, item_ancestors, f"{field_path}[{j}]", item_layer_stack, current_layer_idx=nested_content_layer)
                else:
                    # List items that might be FieldValue
                    from analyzer import FieldValue
                    if isinstance(item, FieldValue):
                        item_display = item.hex if not decode else str(item.val)
                    else:
                        item_display = str(item)
                    item_content = f"[{j}]: {color}{item_display}{AnsiColors.ENDC}"
                    lines.append(f"{list_prefix}{item_connector}{format_line_content(item_content, nested_content_layer)}")
            return

        value = format_value(field_result, metadata)

        if value is not None:
            # Check for resolved pointer value (from offset_of attribute)
            resolved_key = f"{field_result.name}_resolved"
            if field_result.promoted_fields and resolved_key in field_result.promoted_fields:
                resolved = field_result.promoted_fields[resolved_key]
                resolved_val = resolved.val if isinstance(resolved, FieldValue) else resolved
                # Format with inline arrow
                content = f"{AnsiColors.BOLD}{name}{AnsiColors.ENDC}: {color}{value}{AnsiColors.ENDC} → {AnsiColors.OKGREEN}{resolved_val}{AnsiColors.ENDC}"
            else:
                content = f"{AnsiColors.BOLD}{name}{AnsiColors.ENDC}: {color}{value}{AnsiColors.ENDC}"
            lines.append(f"{prefix}{connector}{format_line_content(content, content_layer_idx)}")
        else:
            # Nested structure
            content = f"{AnsiColors.BOLD}{name}{AnsiColors.ENDC}:"
            lines.append(f"{prefix}{connector}{format_line_content(content, content_layer_idx)}")
            if has_nested:
                # Pass down whether this level needs continuation
                new_ancestors = ancestors + [not is_last]
                # Add layer to stack: use current level color for sibling continuation lines
                new_layer_stack = layer_stack + [content_layer_idx]
                add_nested_dict(field_result.decoded_value, new_ancestors, field_path, new_layer_stack, current_layer_idx=nested_content_layer)

    def add_nested_dict(d: dict, ancestors: list[bool], parent_path: str = "", layer_stack: list[int] = None, is_last_sibling: bool = True, current_layer_idx: int = -1):
        """Add a nested dict to the tree. Values are FieldValue objects.

        Args:
            is_last_sibling: Whether this nested dict is the last sibling at its parent level
                           (used when flattening branch-determined fields to preserve tree structure)
        """
        if layer_stack is None:
            layer_stack = []

        # Filter items to only those that match or have matching descendants
        filtered_items = []
        for k, v in d.items():
            field_path = f"{parent_path}.{k}" if parent_path else k
            # Extract the actual value from FieldValue if present
            actual_val = v.val if isinstance(v, FieldValue) else v
            self_matches = field_matches_filter(k, field_path, filter_fields)
            has_nested = isinstance(actual_val, dict)
            descendants_match = has_nested and has_matching_descendants(actual_val, field_path)
            is_list_with_matches = isinstance(actual_val, list) and any(
                isinstance(item, dict) and has_matching_descendants(item, f"{field_path}[{j}]")
                for j, item in enumerate(actual_val)
            )
            if self_matches or descendants_match or is_list_with_matches:
                filtered_items.append((k, v))

        prefix = build_prefix(ancestors, layer_stack)

        for i, (k, v) in enumerate(filtered_items):
            # An item is the last child if it's the last in filtered_items AND the parent is the last sibling
            is_last = (i == len(filtered_items) - 1) and is_last_sibling
            connector_str = "└── " if is_last else "├── "

            # Build field path for metadata lookup
            field_path = f"{parent_path}.{k}" if parent_path else k

            # Check if this field is a layer field - use its position in the chain
            layer_idx = layer_positions.get(k, -1)

            # Determine layer to add to stack for this field's nested content
            # Only changes if this field IS a layer - then children use the new layer color
            if layer_idx >= 0:
                nested_content_layer_idx = layer_idx
            else:
                nested_content_layer_idx = current_layer_idx

            connector = build_connector(connector_str, current_layer_idx)

            # Extract hex and decoded value from FieldValue
            if isinstance(v, FieldValue):
                hex_val = v.hex
                actual_val = v.val
            else:
                hex_val = str(v)
                actual_val = v

            if isinstance(actual_val, dict):
                # Check if this field uses branch-determined size [] and should be flattened
                from coco_ast import BranchDeterminedSize
                # Strip array indices from field_path for metadata lookup
                # e.g., "options[0].rest" -> "options.rest"
                field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
                metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path) or fields_metadata.get(k) if fields_metadata else None
                is_branch_determined = metadata and isinstance(getattr(metadata, 'size', None), BranchDeterminedSize)

                # Check if this structured field has a display formatter
                if decode and metadata:
                    if metadata.attributes and metadata.attributes.display:
                        fmt_name = metadata.attributes.display.name
                        formatted = formatters.format_value(fmt_name, hex_val, decoded_value=actual_val)
                        if formatted:
                            content = f"{k}: {AnsiColors.OKGREEN}{formatted}{AnsiColors.ENDC}"
                            lines.append(f"{prefix}{connector}{format_line_content(content, current_layer_idx)}")
                            continue

                if is_branch_determined:
                    # Flatten: don't show field name, just show its contents at this level
                    add_nested_dict(actual_val, ancestors, parent_path, layer_stack, current_layer_idx=current_layer_idx)
                else:
                    # Normal nested dict: show field name and nest contents
                    content = f"{AnsiColors.BOLD}{k}{AnsiColors.ENDC}:"
                    lines.append(f"{prefix}{connector}{format_line_content(content, current_layer_idx)}")
                    new_ancestors = ancestors + [not is_last]
                    new_layer_stack = layer_stack + [current_layer_idx]
                    add_nested_dict(actual_val, new_ancestors, field_path, new_layer_stack, current_layer_idx=nested_content_layer_idx)
            elif isinstance(actual_val, list):
                content = f"{AnsiColors.BOLD}{k}{AnsiColors.ENDC}: [{len(actual_val)} items]"
                lines.append(f"{prefix}{connector}{format_line_content(content, current_layer_idx)}")
                list_ancestors = ancestors + [not is_last]
                new_layer_stack = layer_stack + [current_layer_idx]
                list_prefix = build_prefix(list_ancestors, new_layer_stack)
                for j, item in enumerate(actual_val):
                    item_is_last = (j == len(actual_val) - 1)
                    item_connector_str = "└── " if item_is_last else "├── "
                    item_connector = build_connector(item_connector_str, nested_content_layer_idx)
                    if isinstance(item, dict):
                        item_content = f"[{j}]:"
                        lines.append(f"{list_prefix}{item_connector}{format_line_content(item_content, nested_content_layer_idx)}")
                        item_ancestors = list_ancestors + [not item_is_last]
                        item_layer_stack = new_layer_stack + [nested_content_layer_idx]
                        add_nested_dict(item, item_ancestors, f"{field_path}[{j}]", item_layer_stack, current_layer_idx=nested_content_layer_idx)
                    else:
                        # List items that are FieldValue
                        if isinstance(item, FieldValue):
                            item_display = item.hex if not decode else str(item.val)
                        else:
                            item_display = str(item)
                        # Apply truncation to list items
                        if isinstance(item_display, str):
                            item_display = truncate_field_value(item_display, field_bytes_limit)
                        item_content = f"[{j}]: {AnsiColors.OKGREEN}{item_display}{AnsiColors.ENDC}"
                        lines.append(f"{list_prefix}{item_connector}{format_line_content(item_content, nested_content_layer_idx)}")
            else:
                color = AnsiColors.OKGREEN
                skip_truncation = False

                # Choose hex or decoded value based on decode flag
                if not decode:
                    formatted_value = hex_val
                else:
                    formatted_value = actual_val

                    # Try to apply display formatter from metadata
                    if fields_metadata:
                        # Strip array indices from field_path for metadata lookup
                        field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
                        metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path) or fields_metadata.get(k)
                        if metadata and metadata.attributes and metadata.attributes.display:
                            fmt_name = metadata.attributes.display.name
                            formatted = formatters.format_value(fmt_name, hex_val)
                            if formatted:
                                formatted_value = formatted
                                skip_truncation = True  # Don't truncate formatted values (like IP addresses)

                    # Apply enum formatting for string values that look like enums
                    if isinstance(formatted_value, str):
                        enum_formatted = format_enum_display(formatted_value)
                        if enum_formatted != formatted_value:
                            formatted_value = enum_formatted
                            skip_truncation = True  # Don't truncate enum values

                # Apply truncation if needed
                if not skip_truncation and isinstance(formatted_value, str):
                    formatted_value = truncate_field_value(formatted_value, field_bytes_limit)

                content = f"{k}: {color}{formatted_value}{AnsiColors.ENDC}"
                lines.append(f"{prefix}{connector}{format_line_content(content, current_layer_idx)}")

    # Process all fields - filter to only show relevant ones
    visible_fields = []
    for i, field in enumerate(validation_result.fields):
        name = field.name if field.name else "+"
        field_path = name
        self_matches = field_matches_filter(name, field_path, filter_fields)
        has_nested = isinstance(field.decoded_value, dict)
        descendants_match = has_nested and has_matching_descendants(field.decoded_value, field_path)
        if self_matches or descendants_match:
            visible_fields.append(field)

    # Determine base layer for root-level fields (use first layer in chain if available)
    base_layer_idx = 0 if protocol_chain else -1

    for i, field in enumerate(visible_fields):
        is_last = (i == len(visible_fields) - 1) and not validation_result.remaining_bytes
        metadata = fields_metadata.get(field.name) if fields_metadata else None
        add_field(field, ancestors=[], metadata=metadata, is_last=is_last, current_layer_idx=base_layer_idx)

    # Add remaining bytes if any (only if no filter or filter is None)
    if validation_result.remaining_bytes and filter_fields is None:
        remaining_connector = build_connector("└── ", base_layer_idx)
        remaining_content = f"{AnsiColors.BOLD}+remaining{AnsiColors.ENDC}: {AnsiColors.FAIL}{validation_result.remaining_bytes}{AnsiColors.ENDC}"
        lines.append(f"{remaining_connector}{format_line_content(remaining_content, base_layer_idx)}")

    return "\n".join(lines)


def get_message_explanation_string_json(validation_result: ValidationResult, fields_metadata: dict = None, decode=False, field_bytes_limit: int = 32):
    """Format validation result as a structured JSON string with a parallel metadata manifest."""
    dissection = {}
    metadata_map = {}

    def process_node(val, hex_val=None, is_valid=True, errors=None, field_path=""):
        """Recursive worker to build the clean tree and populate metadata."""
        if isinstance(val, FieldValue):
            return process_node(val.val, val.hex, is_valid, errors, field_path)

        # Record metadata for this path if it's not the root
        if field_path:
            meta = {"hex": hex_val if hex_val is not None else "", "is_valid": is_valid}
            if errors:
                meta["errors"] = errors
            metadata_map[field_path] = meta

        # Check for branch-determined size [] transparency
        # If metadata shows this field is transparent, its children should be promoted
        from coco_ast import BranchDeterminedSize
        field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
        metadata_obj = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path) if fields_metadata else None
        is_transparent = isinstance(getattr(metadata_obj, 'size', None), BranchDeterminedSize)

        # Apply display formatter if decode=True
        if decode and fields_metadata and hex_val:
            if metadata_obj and metadata_obj.attributes and metadata_obj.attributes.display:
                fmt_name = metadata_obj.attributes.display.name
                formatted = formatters.format_value(fmt_name, hex_val, decoded_value=val)
                if formatted:
                    return formatted

        if isinstance(val, dict):
            res = {}
            for k, v in val.items():
                # Determine child path based on transparency
                child_path = field_path if is_transparent else (f"{field_path}.{k}" if field_path else k)
                
                # Check for child metadata if v is FieldValue
                child_is_valid = True
                child_errors = None
                child_hex = None
                if isinstance(v, FieldValue):
                    child_hex = v.hex
                    # We don't easily have is_valid/errors for nested dict items unless we look them up
                    # but typically if they are in a dict they are part of a valid parent.
                
                processed_val = process_node(v, child_hex, child_is_valid, child_errors, child_path)
                
                if is_transparent and isinstance(processed_val, dict):
                    res.update(processed_val)
                else:
                    res[k] = processed_val
            return res
        
        if isinstance(val, list):
            res = []
            for i, item in enumerate(val):
                child_path = f"{field_path}[{i}]"
                res.append(process_node(item, field_path=child_path))
            return res

        # Scalar value: Apply truncation if field_bytes_limit > 0
        if field_bytes_limit > 0 and isinstance(val, str) and not (decode and val.startswith("0x")):
            # Don't truncate if it looks like an enum already formatted
            if not ("." in val and not val.startswith("0x")):
                return truncate_field_value(val, field_bytes_limit)

        return val

    # Build the dissection tree from top-level fields
    for field in validation_result.fields:
        # Determine if this top-level field is transparent
        from coco_ast import BranchDeterminedSize
        metadata_obj = fields_metadata.get(field.name) if fields_metadata else None
        is_transparent = isinstance(getattr(metadata_obj, 'size', None), BranchDeterminedSize)

        processed = process_node(
            field.decoded_value, 
            field.hex_value, 
            field.is_valid, 
            field.errors, 
            field.name
        )

        if is_transparent and isinstance(processed, dict):
            dissection.update(processed)
        else:
            dissection[field.name] = processed

    data = {
        "message_name": validation_result.message_name,
        "is_valid": validation_result.is_valid,
        "protocol_chain": validation_result.protocol_chain,
        "dissection": dissection,
        "metadata": metadata_map
    }

    if validation_result.remaining_bytes:
        data["remaining_bytes"] = truncate_field_value(validation_result.remaining_bytes, field_bytes_limit) if field_bytes_limit > 0 else validation_result.remaining_bytes
        metadata_map["+remaining"] = {
            "hex": validation_result.remaining_bytes,
            "is_valid": False,
            "errors": ["Unconsumed bytes remaining"]
        }

    return json.dumps(data, indent=2)


def get_message_explanation_string_porcelain(validation_result: ValidationResult, fields_metadata: dict = None, decode=False, filter_fields=None, coco_file=None, field_bytes_limit: int = 32, message_name: str = None):
    """Format validation result as porcelain (machine-readable, tab-separated columns).

    Format: STATUS\tPATH\tHEX\tDECODED
    STATUS is OK or ERR. Empty values are represented by a hyphen '-'.
    """
    # Collect rows as tuples: (status, path, hex, decoded)
    rows = []

    # Add message name header row if provided
    if message_name:
        status = "OK" if validation_result.is_valid else "ERR"
        rows.append((status, message_name, "-", "-"))

    def format_decoded(value, hex_val: str, metadata=None) -> str:
        """Format decoded value for display."""
        if not decode or value is None:
            return "-"
        if isinstance(value, dict):
            return "-"  # Nested structures handled separately
        if isinstance(value, list):
            return f"[{len(value)} items]"

        result = str(value)

        # Apply display formatter if available
        if decode and metadata and metadata.attributes and metadata.attributes.display:
            fmt_name = metadata.attributes.display.name
            formatted = formatters.format_value(fmt_name, hex_val, decoded_value=value)
            if formatted:
                result = formatted

        # Apply truncation
        if field_bytes_limit > 0:
            result = truncate_field_value(result, field_bytes_limit)

        return result if result else "-"

    def flatten_field(field_result: DecodeResult, path: str = "", metadata=None):
        """Recursively flatten a field result into lines."""
        name = field_result.name if field_result.name else "+remaining"
        field_path = f"{path}.{name}" if path else name

        # Check filter
        if filter_fields is not None:
            if not field_matches_filter(name, field_path, filter_fields):
                # Check if any descendants match
                if not isinstance(field_result.decoded_value, dict):
                    return

        status = "OK" if field_result.is_valid else "ERR"
        hex_val = field_result.hex_value if field_result.hex_value else "-"

        # Show "(none)" for empty scalar fields (0 bytes) when decoding
        # Lists should show "[0 items]" instead via format_decoded()
        if decode and (not field_result.hex_value or len(field_result.hex_value) == 0) and not isinstance(field_result.decoded_value, list):
            decoded = "(none)"
        else:
            decoded = format_decoded(field_result.decoded_value, field_result.hex_value, metadata)

        if field_bytes_limit > 0 and hex_val != "-":
            hex_val = truncate_field_value(hex_val, field_bytes_limit)

        # Check if this structured field has a display formatter
        if decode and metadata:
            if metadata.attributes and metadata.attributes.display:
                fmt_name = metadata.attributes.display.name
                original_hex = field_result.hex_value
                formatted = formatters.format_value(fmt_name, original_hex, decoded_value=field_result.decoded_value)
                if formatted:
                    rows.append((status, field_path, hex_val, formatted))
                    return

        # Output this field if it's a leaf or has a simple value
        if not isinstance(field_result.decoded_value, dict):
            rows.append((status, field_path, hex_val, decoded))
        else:
            # Nested structure - recurse
            flatten_dict(field_result.decoded_value, field_path, field_result.is_valid)

    def flatten_dict(d: dict, parent_path: str, parent_valid: bool = True):
        """Recursively flatten a nested dict."""
        for k, v in d.items():
            field_path = f"{parent_path}.{k}"

            # Check filter
            if filter_fields is not None and not field_matches_filter(k, field_path, filter_fields):
                # Check descendants for dicts
                actual_val = v.val if isinstance(v, FieldValue) else v
                if isinstance(actual_val, dict):
                    flatten_dict(actual_val, field_path, parent_valid)
                continue

            # Extract from FieldValue
            if isinstance(v, FieldValue):
                hex_val = v.hex
                actual_val = v.val
            else:
                hex_val = str(v) if not isinstance(v, (dict, list)) else ""
                actual_val = v

            status = "OK" if parent_valid else "ERR"

            if isinstance(actual_val, dict):
                # Check if this structured field has a display formatter
                if decode and fields_metadata:
                    field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
                    metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path) or fields_metadata.get(k)
                    if metadata and metadata.attributes and metadata.attributes.display:
                        fmt_name = metadata.attributes.display.name
                        formatted = formatters.format_value(fmt_name, hex_val, decoded_value=actual_val)
                        if formatted:
                            rows.append((status, field_path, hex_val if hex_val else "-", formatted))
                            continue
                
                flatten_dict(actual_val, field_path, parent_valid)
            elif isinstance(actual_val, list):
                rows.append((status, field_path, "-", f"[{len(actual_val)} items]"))
                for i, item in enumerate(actual_val):
                    item_path = f"{field_path}[{i}]"
                    if isinstance(item, dict):
                        flatten_dict(item, item_path, parent_valid)
                    elif isinstance(item, FieldValue):
                        item_hex = truncate_field_value(item.hex, field_bytes_limit) if field_bytes_limit > 0 else item.hex
                        item_val = str(item.val) if decode else "-"
                        if decode and field_bytes_limit > 0:
                            item_val = truncate_field_value(item_val, field_bytes_limit)
                        rows.append((status, item_path, item_hex if item_hex else "-", item_val if item_val else "-"))
                    else:
                        item_str = str(item) if decode else "-"
                        if decode and field_bytes_limit > 0:
                            item_str = truncate_field_value(item_str, field_bytes_limit)
                        rows.append((status, item_path, "-", item_str if item_str else "-"))
            else:
                # Apply display formatter if available
                decoded_str = str(actual_val) if (decode and actual_val is not None) else "-"
                if decode and fields_metadata:
                    field_path_no_indices = re.sub(r'\[\d+\]', '', field_path)
                    metadata = fields_metadata.get(field_path_no_indices) or fields_metadata.get(field_path) or fields_metadata.get(k)
                    if metadata and metadata.attributes and metadata.attributes.display:
                        fmt_name = metadata.attributes.display.name
                        original_hex = v.hex if isinstance(v, FieldValue) else hex_val
                        formatted = formatters.format_value(fmt_name, original_hex, decoded_value=actual_val)
                        if formatted:
                            decoded_str = formatted

                if field_bytes_limit > 0:
                    if hex_val: hex_val = truncate_field_value(hex_val, field_bytes_limit)
                    if decoded_str != "-": decoded_str = truncate_field_value(decoded_str, field_bytes_limit)
                
                rows.append((status, field_path, hex_val if hex_val else "-", decoded_str if decoded_str else "-"))

    # Process all fields
    for field in validation_result.fields:
        metadata = fields_metadata.get(field.name) if fields_metadata else None
        flatten_field(field, "", metadata)

    # Add remaining bytes if any
    if validation_result.remaining_bytes:
        remaining = validation_result.remaining_bytes
        if field_bytes_limit > 0:
            remaining = truncate_field_value(remaining, field_bytes_limit)
        rows.append(("ERR", "+remaining", remaining, "-"))

    # Calculate column widths for pretty alignment while keeping Tabs for parsing
    if not rows:
        return ""

    col_widths = [
        max(len(row[0]) for row in rows),  # status
        max(len(row[1]) for row in rows),  # path
        max(len(row[2]) for row in rows),  # hex
    ]

    lines = []
    for status, path, hex_val, decoded in rows:
        # Format: STATUS [pad] \t PATH [pad] \t HEX [pad] \t DECODED
        # The Tab ensures unambiguous parsing even if decoded column has spaces
        line = f"{status:<{col_widths[0]}}\t{path:<{col_widths[1]}}\t{hex_val:<{col_widths[2]}}\t{decoded}"
        lines.append(line.rstrip())

    return "\n".join(lines)


def get_message_explanation_string(validation_result, validation_log_dict = None, fmt="oneline", filter_fields = None, decode = False, no_newlines=False, field_bytes_limit: int = 32):

    _, validation_result_dict, validation_diff_dict, __, ___ = validation_result

    if fmt == "oneline":
        result_string = get_message_explanation_string_oneline(validation_result, filter_fields, decode=decode, no_newlines=no_newlines, field_bytes_limit=field_bytes_limit)
    elif fmt == "compact":
        result_string = get_message_explanation_string_compact(validation_result, filter_fields, decode=decode, no_newlines=no_newlines, field_bytes_limit=field_bytes_limit)
    else:
        result_string = get_message_explanation_string_multiline(validation_result, filter_fields, decode=decode, no_newlines=no_newlines, field_bytes_limit=field_bytes_limit)

    logs_string = ""
    if validation_log_dict is not None and len(validation_log_dict) > 0:
        for field_name, log_message_list in validation_log_dict.items():
            logs_string += f"- {field_name}:\n"

            #print([f"    - {log_message}" for log_message in log message_list])
            logs_string += "\n".join([f"    - {log_message}" for log_message in log_message_list])
            logs_string += "\n"

    return logs_string + result_string

def find_message_rules(message_name, cocodoc):
    for message_rules in cocodoc.all_messages_rules_tokenized:
        assert(rule_is_title([message_rules[0][0]]))
        if message_name == title_rule_get_name(message_rules[0]):
            return message_rules

def split_fields_for_create_message(message_name, message_rules_tokenized):
    needed_input_fields = []
    length_fields = []
    fixed_fields = []
    
    for rule in message_rules_tokenized[1:]:
        if rule_is_field(rule):
            byte_symbol = field_rule_get_byte_symbol(rule)

            
            if field_rule_is_lengthof(rule):
                length_fields.append(field_rule_get_field_name(rule))
            elif byte_symbol_is_valid_hex(byte_symbol):
                fixed_fields.append(field_rule_get_field_name(rule))
            else:
                needed_input_fields.append(field_rule_get_field_name(rule))
    

    return needed_input_fields, length_fields, fixed_fields

def create_message(message_name, cocodoc, input_dict = None):
    message_rules = find_message_rules(message_name, cocodoc)
    message_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    message_rules = perform_subtypeof_overrides(message_rules, cocodoc.all_messages_rules_tokenized)
    
    needed_input_fields, length_fields, fixed_fields = split_fields_for_create_message(message_name, message_rules)
        
    message_fields_dict = OrderedDict()
    lengths_dict = {}
    
    multifield_names_stack = []
    accumulated_multifield_lengths = {}
    
    if input_dict is not None:
        input_fields_stack = input_dict["message_fields"][::-1]
            
    for rule in message_rules:
        if rule_is_field(rule):
            
            field_name = field_rule_get_field_name(rule)
            byte_symbol = field_rule_get_byte_symbol(rule)
            
            if field_name in fixed_fields:
                message_fields_dict[field_name] = byte_symbol.lower()
                
                for multifield in multifield_names_stack:
                    accumulated_multifield_lengths[multifield] += len(byte_symbol)//2
                    
            elif field_name in length_fields:
                message_fields_dict[field_name] = None
                
                for multifield in multifield_names_stack:
                    accumulated_multifield_lengths[multifield] += len(byte_symbol)//2
                    
            elif field_name in needed_input_fields:
                if input_dict is not None:
                    field_recipe = input_fields_stack.pop()
                    
                    value = ""
                    
                    if "value_is_hex_string" not in field_recipe:
                        field_recipe["value_is_hex_string"] = not field_recipe["value_is_file_path"]
                    
                    if field_recipe["value_is_file_path"] == True:
                        if field_recipe["value_is_hex_string"] == False:
                            with open(field_recipe["value"], mode="rb") as f:
                                value = f.read()
                        else:
                            with open(field_recipe["value"]) as f:
                                value = f.read()
                    else:
                        value = field_recipe["value"]
                    
                    if field_recipe["value_is_hex_string"] == False:
                        value = value.hex()
                    
                    if field_recipe["should_encode"] == True:
                        value = field_encode(rule, value)
                        
                    hex_string = value #TODO assert rule complies parent
                    
                else:
                    hex_string = input(f"Enter hex string for field '{field_name}': ") 
                    
                assert is_valid_message_input(hex_string), f"Malformed hex string for '{field_name}': '{hex_string}'"
                message_fields_dict[field_name] = hex_string.lower()
                lengths_dict[field_name] = len(hex_string)//2
                
                for multifield in multifield_names_stack:
                    accumulated_multifield_lengths[multifield] += len(hex_string)//2
                
            else:
                raise RuntimeError(f"Unexpected {rule=} in message rules for message {title_rule_get_name(message_rules[0])}")
        elif rule_is_multifieldstart(rule):
            multifield_name = get_multifieldstart_full_name(rule[1])
            multifield_names_stack.append(multifield_name)
            accumulated_multifield_lengths[multifield_name] = 0
        elif rule_is_multifieldend(rule):
            mfs_name = multifield_names_stack[-1]
            mfe_name = get_multifieldend_full_name(rule[1])
            
            assert mfs_name == mfe_name, f"Unexpected multifield end, {rule=}, {multifield_names_stack[-1]=}"
            
            multifield_names_stack.pop()
    
    for k, v in accumulated_multifield_lengths.items():
        # For now we will use the short names to keep it simple, SHOULD FIX it in the future
        mf_name = k[k.find(".")+1:].strip()
        lengths_dict[mf_name] = v

    #FILL LENGTHOF FIELDS:
    for field_name in length_fields:
        for i, rule in enumerate(message_rules):
            if rule_is_field(rule) and field_rule_is_lengthof(rule):
                field_name = field_rule_get_field_name(rule)
                target_field_for_length = lengthof_rule_get_target_field_name(rule)
                
                length = lengths_dict[target_field_for_length]
                
                byte_symbol = field_rule_get_byte_symbol(rule)
                assert byte_symbol_is_XX_rule_type(byte_symbol)
                length_field_strlength = len(byte_symbol)
                
                #get_length_hex_string = lambda x: (hex(x)[2:] if len(hex(x))%2 == 0 else "0" + hex(x)[2:]).lower()
                #length_hex_string = get_length_hex_string(length) #BIGENDIAN
                length_hex_string = field_encode(rule, str(length))
                #print(f"HOLA : {length_hex_string=}")
                
                #raise RuntimeError("ASDFASDF")
                
                if len(length_hex_string) > length_field_strlength:
                    raise RuntimeError(f"length {length_hex_string} for {rule=} would overflow the length field")
                elif len(length_hex_string) < length_field_strlength:
                    length_hex_string = "0"*(length_field_strlength-len(length_hex_string)) + length_hex_string
                elif len(length_hex_string) == length_field_strlength:
                    pass
                
                #SWAP IF LITTLE ENDIAN:
                #params = rule[2:]
                #for param in params:
                    #if "lengthof " in param:
                        #if "littleendian:lengthof " in param or "le:lengthof " in param:
                            #length_hex_string = "".join(re.findall('..',length_hex_string)[::-1])
                
                message_fields_dict[field_name] = length_hex_string

    #pprint(message_fields_dict)
    
    
    ## Check if all generated fields comply with the rules
    for rule in message_rules:
        if rule_is_field(rule):
            field_name = field_rule_get_field_name(rule)
            message_field_aux_rule = [message_fields_dict[field_name], field_name]
            
            if not field_rule_complies_parent(message_field_aux_rule, rule):
                raise ValueError(f"Input Error: field rule {message_field_aux_rule} doesn't comply with parent rule {rule}")
            
            
    ## Build message
    message = ""
    for v in message_fields_dict.values():
        message += v
        
    ##REDUNDANT CHECK: We already checked fields comply with rules, but we validate the full message just in case
    validate_result = validate_message_by_name(message_name, message, cocodoc)
    
    if validate_result[0] == False:
        raise RuntimeError(f"Invalid message generated. Call protococo check {message_name} {message} to see dissection")

    return message

# max_chunk_size: max number of bytes for each chunk
# message_format: can be 'hex' or 'bytes'
def split_message(message, max_chunk_size, message_format):
    result = []

    message_str_len = len(message)
    chunk_str_offset = 0
    max_chunk_str_len = 2 * max_chunk_size if message_format == "hex" else max_chunk_size
    if max_chunk_str_len > message_str_len:
        max_chunk_str_len = message_str_len

    while True:
        if chunk_str_offset + max_chunk_str_len < message_str_len:
            result.append(message[chunk_str_offset : chunk_str_offset + max_chunk_str_len])
            chunk_str_offset += max_chunk_str_len
        else:
            if len(message[chunk_str_offset:]) > 0:
                result.append(message[chunk_str_offset:])
            break
    
    return result

def message_recipe_find_field_index(message_recipe, field_name):
    for i, field in enumerate(message_recipe["message_fields"]):
        if field["field_name"] == field_name:
            return i

def transport(cocodoc, message_recipe):

    message_name = message_recipe["message_name"]
    payload_field = message_recipe["transport"]["payload_field"]
    sequence_field = message_recipe["transport"].get("sequence_field")
    payload_mtu = message_recipe["transport"].get("mtu")
    rolling_state = message_recipe["transport"].get("rolling_state")


    payload_idx = message_recipe_find_field_index(message_recipe, payload_field)
    if payload_idx is None:
        print(f"Can't find payload field '{payload_field}' in recipe.message_fields:")
        pprint(message_recipe["message_fields"])
        return []
    sequence_idx = None if sequence_field is None else message_recipe_find_field_index(message_recipe, payload_field)

    payloads = None

    if "value_is_hex_string" not in message_recipe["message_fields"][payload_idx]:
        message_recipe["message_fields"][payload_idx]["value_is_hex_string"] = not message_recipe["message_fields"][payload_idx]["value_is_file_path"]
    
    value_format = "hex" if message_recipe["message_fields"][payload_idx]["value_is_hex_string"] else "bytes"

    if message_recipe["message_fields"][payload_idx]["value_is_file_path"] == True:
        if message_recipe["message_fields"][payload_idx]["value_is_hex_string"] == False:
            if message_recipe["message_fields"][payload_idx]["value"] == "-":
                payloads = [sys.stdin.buffer.read()]
            else:
                with open(message_recipe["message_fields"][payload_idx]["value"], mode="rb") as f:
                    payloads = [f.read()]
        else:
            if message_recipe["message_fields"][payload_idx]["value"] == "-":
                payloads = sys.stdin.read().split()
            else:
                with open(message_recipe["message_fields"][payload_idx]["value"]) as f:
                    payloads = [f.read()]
        
        message_recipe["message_fields"][payload_idx]["value_is_file_path"] = False
    else:
        payloads = [message_recipe["message_fields"][payload_idx]["value"]]

    chunks = []
    if payload_mtu is not None:
        for payload in payloads:
            payload_chunks = split_message(payload, payload_mtu, value_format)
            
            state = {

            }
            if rolling_state is not None:
                for k, v in rolling_state.items():
                    if isinstance(v, str):
                        arg = v.split()
                        if arg[0] == "sequence":
                            state[k] = [i for i in range(int(arg[1]), len(payload_chunks), int(arg[2]))]

            # for chunk in payload_chunks:
            #     if 


            chunks += payload_chunks

    else:
        chunks += payloads

    result = []
    # sequence_number = 0
    for chunk in chunks:
        message_recipe["message_fields"][payload_idx]["value"] = chunk
        # if sequence_field is not None:
        #     message_recipe["message_fields"][sequence_idx] = field_encode()... sequence_number
        #     sequence_number += 1
        result.append(create_message(message_name, cocodoc, message_recipe))
    
    return result

def get_input_schema(message_name, cocodoc):    
    message_rules = find_message_rules(message_name, cocodoc)
    message_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    message_rules = perform_subtypeof_overrides(message_rules, cocodoc)
    
    needed_input_fields, length_fields, fixed_fields = split_fields_for_create_message(message_name, message_rules)

    fields_schema = []
    for field_name in needed_input_fields:
        fields_schema.append({
            "field_name" : field_name,
            "value" : "input field value or path/to/file (relative to script execution dir)",
            "value_is_file_path" : False,
            "should_encode" : False
            #"value_is_hex_string" : True,
        })
    
    schema = [{"message_name" : message_name,
               "message_fields" : fields_schema}]
    
    
    return schema


"""

        DEFAULT ENTRYPOINT

"""
def cli_main():
    args = docopt(__doc__, version=f"protococo {__version__}")

    ret = 0

    # Parse the .coco file using new v1.0 parser
    try:
        coco_file = parse(args["--cocofile"])
    except ParseError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File not found: {args['--cocofile']}", file=sys.stderr)
        sys.exit(1)

    # Determine whether to follow offset jumps (defaults to --decode value if --follow-pointers not set)
    follow_pointers = args.get("--follow-pointers")
    if follow_pointers is None:
        follow_pointers = args["--decode"]

    decoder = Decoder(coco_file, follow_offset_jumps=follow_pointers)

    # Get max message name length for formatting
    max_name_len = max(len(m.name) for m in coco_file.messages) if coco_file.messages else 0

    # Parse field bytes limit (default 32, 0=unlimited)
    field_bytes_limit = int(args.get("-L") or args.get("--field-bytes-limit") or 32)

    if args["tree"] == True:
        # Build and print layer message containment tree based on match clauses
        from treelib import Tree
        from coco_ast import EnumTypeRef

        # Get all layer messages
        layer_messages = {msg.name for msg in coco_file.messages if msg.is_layer}

        def get_contained_layers(msg) -> list[tuple[str, str]]:
            """Find layer messages contained via match clauses.
            Returns list of (field_name, message_name) tuples.
            """
            contained = []
            fields = decoder.resolve_message(msg)

            def check_fields(fields_list):
                for field in fields_list:
                    # Check if field type is a layer message
                    if isinstance(field.type, EnumTypeRef):
                        type_name = field.type.enum_name
                        if type_name in layer_messages:
                            contained.append((field.name, type_name))

                    # Check match clause branches
                    if field.match_clause:
                        for branch in field.match_clause.branches:
                            if branch.fields:
                                check_fields(branch.fields)

                    # Check structure body
                    if field.structure_body:
                        check_fields(field.structure_body)

            check_fields(fields)
            return contained

        # Build containment graph
        containment = {}
        for msg in coco_file.messages:
            if msg.is_layer:
                containment[msg.name] = get_contained_layers(msg)

        # Find root layer messages (not contained by any other)
        all_contained = set()
        for contained_list in containment.values():
            for _, msg_name in contained_list:
                all_contained.add(msg_name)
        roots = [name for name in layer_messages if name not in all_contained]

        # Build tree with full expansion (allow duplicates via unique node IDs)
        tree = Tree()
        node_counter = [0]

        def add_subtree(msg_name: str, parent_id: str, depth: int = 0):
            # Limit depth to prevent infinite recursion in case of cycles
            if depth > 10:
                return

            node_counter[0] += 1
            node_id = f"{msg_name}_{node_counter[0]}"
            tree.create_node(msg_name, node_id, parent=parent_id)

            for field_name, child_msg in containment.get(msg_name, []):
                add_subtree(child_msg, node_id, depth + 1)

        # If single root, use it directly; otherwise use "protocols" wrapper
        if len(roots) == 1:
            root_name = roots[0]
            tree.create_node(root_name, "root")
            for field_name, child_msg in containment.get(root_name, []):
                add_subtree(child_msg, "root")
        else:
            tree.create_node("protocols", "root")
            for root in sorted(roots):
                add_subtree(root, "root")

        tree.show()

    elif args["mspec"] == True:
        # Print message specification
        from coco_ast import (
            IntegerType, BytesType, StringType, PadType, BitFieldType, EnumTypeRef,
            LiteralSize, FieldRefSize, VariableSize, GreedySize, BranchDeterminedSize
        )

        def format_type(field_type):
            if isinstance(field_type, IntegerType):
                base = field_type.base
                if field_type.endian:
                    return f"{base}:{field_type.endian.value}"
                return base
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
            return str(field_type)

        msg = coco_file.get_message(args["<message_name>"])
        if msg is None:
            print(f"Message '{args['<message_name>']}' not found")
            ret = 1
        else:
            fields = decoder.resolve_message(msg)
            print(f"message {msg.name}" + (f" extends {msg.parent}" if msg.parent else "") + " {")
            for field in fields:
                type_str = format_type(field.type)
                size_str = ""
                if field.size:
                    if isinstance(field.size, LiteralSize):
                        size_str = f"[{field.size.value}]"
                    elif isinstance(field.size, FieldRefSize):
                        size_str = f"[{field.size.field_name}]"
                    elif isinstance(field.size, GreedySize):
                        size_str = "[...]"
                    elif isinstance(field.size, BranchDeterminedSize):
                        size_str = "[]"
                    elif isinstance(field.size, VariableSize):
                        size_str = "[]"
                default_str = ""
                if field.default_value is not None:
                    if isinstance(field.default_value, int):
                        default_str = f" = 0x{field.default_value:02X}"
                    else:
                        default_str = f" = {field.default_value}"
                print(f"  {type_str} {field.name}{size_str}{default_str}")
            print("}")

    elif args["wireshark"] == True:
        # Generate Wireshark Lua dissector
        from wireshark_gen import generate_lua_dissector

        message_name = args["<message_name>"]
        stack_mode = args.get("--stack", False)
        try:
            lua_code = generate_lua_dissector(coco_file, message_name, stack_mode=stack_mode)
            print(lua_code)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            ret = 1

    elif args["check"] == True:
        messages_input = [sys.stdin.read()] if not args["<message_hex_string>"] else args["<message_hex_string>"]

        filter_fields = [f.strip() for f in args["--dissect-fields"].split(",")] if args["--dissect-fields"] is not None else None

        for message_hex_string in messages_input:
            result = decoder.validate_by_name(args["<message_name>"], message_hex_string)

            # Apply layer filtering if requested
            if args["--layer"]:
                filtered_result = extract_layer_subtree(result, args["--layer"], decoder)
                if filtered_result is None:
                    print(f"Error: layer '{args['--layer']}' not found in protocol chain", file=sys.stderr)
                    continue
                result = filtered_result

            if args["--format"] == "porcelain":
                # Porcelain format: machine-readable, space-padded columns
                msg = coco_file.get_message(args["<message_name>"])
                fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                print(get_message_explanation_string_porcelain(result, fields_metadata, decode=args["--decode"], filter_fields=filter_fields, coco_file=coco_file, field_bytes_limit=field_bytes_limit, message_name=result.message_name))
            elif args["--format"] == "json":
                # JSON format: structured data
                msg = coco_file.get_message(args["<message_name>"])
                fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                print(get_message_explanation_string_json(result, fields_metadata, decode=args["--decode"], field_bytes_limit=field_bytes_limit))
            elif args["--tree"] or args["--format"] == "tree":
                # Build field metadata for display formatters (including nested)
                msg = coco_file.get_message(args["<message_name>"])
                fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                print(get_message_explanation_string_tree(result, fields_metadata, decode=args["--decode"], filter_fields=filter_fields, coco_file=coco_file, field_bytes_limit=field_bytes_limit, protocol_chain=result.protocol_chain, layer_colors=args["--layer-colors"]))
            else:
                # Build field metadata for display formatters
                msg = coco_file.get_message(args["<message_name>"])
                fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                validate_result = validation_result_to_tuple(result, fields_metadata, coco_file, args["--decode"])

                explanation_logs = None
                if args["--verbose"] == True:
                    explanation_logs = validate_result[3]

                print(get_message_explanation_string(validate_result, explanation_logs, fmt=args["--format"], filter_fields=filter_fields, decode=args["--decode"], no_newlines=args["--decode-no-newlines"], field_bytes_limit=field_bytes_limit))

            if not result.is_valid:
                ret = 1

    elif args["find"] == True:
        messages_input = sys.stdin.read().split() if not args["<message_hex_string>"] else args["<message_hex_string>"]
        for message_hex_string in messages_input:
            results = decoder.identify_message(message_hex_string)

            # Apply layer filtering if requested - filter candidates before processing
            if args["--layer"]:
                filtered_results = []
                for result in results:
                    filtered_result = extract_layer_subtree(result, args["--layer"], decoder)
                    if filtered_result is not None:
                        filtered_results.append(filtered_result)

                # If no candidates have the layer, print error and skip
                if not filtered_results:
                    print(f"Error: layer '{args['--layer']}' not found in protocol chain", file=sys.stderr)
                    continue

                results = filtered_results

            for i, result in enumerate(results):
                msg = coco_file.get_message(result.message_name)
                fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                validate_tuple = validation_result_to_tuple(result, fields_metadata, coco_file, args["--decode"])
                color = AnsiColors.BOLD + AnsiColors.OKGREEN if result.is_valid else AnsiColors.BOLD + AnsiColors.FAIL

                filter_fields = [f.strip() for f in args["--dissect-fields"].split(",")] if args["--dissect-fields"] is not None else None

                # Porcelain format: machine-readable, space-padded columns
                if args["--format"] == "porcelain":
                    if args["--dissect"] == True or filter_fields is not None:
                        msg = coco_file.get_message(result.message_name)
                        fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                        chain_name = ":".join(result.protocol_chain) if result.protocol_chain else result.message_name
                        print(get_message_explanation_string_porcelain(result, fields_metadata, decode=args["--decode"], filter_fields=filter_fields, coco_file=coco_file, field_bytes_limit=field_bytes_limit, message_name=chain_name))
                    else:
                        # Just message name, no field dissection
                        status = "OK" if result.is_valid else "ERR"
                        chain_name = ":".join(result.protocol_chain) if result.protocol_chain else result.message_name
                        print(f"{status}  {chain_name}")
                    if not result.is_valid:
                        ret = 1
                    if args["--list"] == False:
                        break
                    continue

                # JSON format: structured data
                if args["--format"] == "json":
                    msg = coco_file.get_message(result.message_name)
                    fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                    print(get_message_explanation_string_json(result, fields_metadata, decode=args["--decode"], field_bytes_limit=field_bytes_limit))
                    if not result.is_valid:
                        ret = 1
                    if args["--list"] == False:
                        break
                    continue

                explanation = ""
                if args["--dissect"] == True or filter_fields is not None:
                    if args["--tree"] or args["--format"] == "tree":
                        # Build field metadata for display formatters (including nested)
                        msg = coco_file.get_message(result.message_name)
                        fields_metadata = collect_field_metadata(decoder, msg) if msg else {}
                        explanation = "\n" + get_message_explanation_string_tree(result, fields_metadata, decode=args["--decode"], filter_fields=filter_fields, coco_file=coco_file, field_bytes_limit=field_bytes_limit, protocol_chain=result.protocol_chain, layer_colors=args["--layer-colors"])
                    elif args["--verbose"] == True:
                        explanation = "\n" + get_message_explanation_string(validate_tuple, validate_tuple[3], fmt=args["--format"], filter_fields=filter_fields, decode=args["--decode"], no_newlines=args["--decode-no-newlines"], field_bytes_limit=field_bytes_limit)
                    else:
                        explanation = get_message_explanation_string(validate_tuple, None, fmt=args["--format"], filter_fields=filter_fields, decode=args["--decode"], no_newlines=args["--decode-no-newlines"], field_bytes_limit=field_bytes_limit)

                    if not result.is_valid:
                        ret = 1

                # Use protocol chain if available, otherwise message name
                if result.protocol_chain:
                    name_string = ":".join(result.protocol_chain)
                else:
                    name_string = result.message_name
                number_of_whitespaces = max_name_len - len(name_string) + 2

                if args["--list"] == False:
                    if args["--tree"] or args["--format"] == "tree":
                        print(color + f"[{name_string}]" + AnsiColors.ENDC)
                        print(explanation)
                    elif args["--format"] == "oneline" or args["--format"] == "compact":
                        print(color  + f"[{name_string}]" + AnsiColors.ENDC + " "*number_of_whitespaces + explanation)
                    else:
                        print(color  + f"[{name_string}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
                    break
                else:
                    if args["--tree"] or args["--format"] == "tree":
                        print(color + f"- {i}: [{name_string}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
                    elif args["--format"] == "oneline" or args["--format"] == "compact":
                        print(color  + f"{str(i): >8}: [{name_string}]" + AnsiColors.ENDC + " "*number_of_whitespaces + explanation)
                    else:
                        print(color  + f"- {i}: [{name_string}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
    elif args["create"] == True:
        encoder = Encoder(coco_file)

        if args["<message_name>"] is not None and args["<message_name>"] != []:
            message_name = args["<message_name>"]
            msg = coco_file.get_message(message_name)
            if msg is None:
                print(f"Error: Message '{message_name}' not found")
                ret = 1
            else:
                # Interactive mode - prompt for input fields
                category = encoder.categorize_fields(msg)
                specs = encoder.get_input_specs(msg)

                if not specs:
                    # No input needed, just create
                    try:
                        result = encoder.create_message(msg, {})
                        print(result)
                    except Exception as e:
                        print(f"Error: {e}")
                        ret = 1
                else:
                    # Prompt for each input field
                    input_values = {}
                    for spec in specs:
                        prompt = f"Enter value for '{spec.name}' ({spec.field_type}): "
                        value = input(prompt)

                        # Parse value based on type
                        if spec.field_type in ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"):
                            if value.startswith("0x"):
                                input_values[spec.name] = int(value, 16)
                            else:
                                input_values[spec.name] = int(value)
                        else:
                            input_values[spec.name] = value

                    try:
                        result = encoder.create_message(msg, input_values)
                        print(result)
                    except Exception as e:
                        print(f"Error: {e}")
                        ret = 1

        elif args["--from-json"] is not None:
            json_file_path = args["--from-json"]

            try:
                with open(json_file_path) as f:
                    full_recipe = json.load(f)

                # Handle both single recipe and list of recipes
                if isinstance(full_recipe, dict):
                    full_recipe = [full_recipe]

                for message_recipe in full_recipe:
                    message_name = message_recipe["message_name"]
                    msg = coco_file.get_message(message_name)
                    if msg is None:
                        print(f"Error: Message '{message_name}' not found")
                        ret = 1
                        continue

                    # Build input values from recipe
                    input_values = {}
                    for field_recipe in message_recipe.get("message_fields", []):
                        field_name = field_recipe["field_name"]
                        value = field_recipe["value"]

                        # Handle file path
                        if field_recipe.get("value_is_file_path", False):
                            if field_recipe.get("value_is_hex_string", True):
                                with open(value) as f:
                                    value = f.read().strip()
                            else:
                                with open(value, "rb") as f:
                                    value = f.read().hex()

                        input_values[field_name] = value

                    try:
                        result = encoder.create_message(msg, input_values)
                        print(result)
                    except Exception as e:
                        print(f"Error creating {message_name}: {e}")
                        ret = 1

            except FileNotFoundError:
                print(f"Error: JSON file not found: {json_file_path}")
                ret = 1
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON: {e}")
                ret = 1

    elif args["json-recipe"] == True:
        encoder = Encoder(coco_file)
        message_names = args["<message_names>"]

        recipes = []
        for message_name in message_names:
            msg = coco_file.get_message(message_name)
            if msg is None:
                print(f"Error: Message '{message_name}' not found", file=sys.stderr)
                ret = 1
                continue
            recipes.append(encoder.get_json_recipe(msg))

        if recipes:
            print(json.dumps(recipes, indent=2))
                
        
        
    sys.stdout.flush()
    os._exit(ret)
    

    
    
    
    



#TODO warnings: 2 equivalent messages in rules
#TODO error: 2 fields with same name in rules
#TODO feature: complete tree in multiline check/dissect
#TODO ?: identificación certera del mensaje en función del message_type???
#TODO fix: falla cuando un lengthof cae dentro de una ellipsis o más allá del fin del mensaje en mensajes incompletos
#TODO improvement: cambiar el --dissect-fields por un arg adicional opcional filter-fields que tb funcione con el check
#TODO feature: #include message, #includepart message
#TODO feature: X16
#TODO improvement: N field of missing length could be OK sometimes
#TODO feature: endswith instead of length
#TODO feature: --input-format=bin, --input-format=hex-string
#TODO feature: create message
#TODO feature: regex matcher for ascii rule
#TODO tests: Bash diff tests
#TODO fix: Logger for --verbose fix
#TODO feature: --input-format=json
#TODO feature: output-format==ptable
#TODO optimization: don't tokenize rules for each validation
#TODO fix: overriden fields with different params, like encodedas
#TODO optimization: if a parent rule fails, don't check subtypes. --list'd not be possible
#TODO refactor: CocoDocument, CocoMessageSpec, CocoRule, CocoParser, CocoAnalyzer, CocoCLI
#TODO improvement: cocofile checks: no "." in any rule
#TODO fix: problem decoding littleendian from rule between parenthesis, example: (0)   #encodedas littlendian
#TODO fix: override a 4 byte field with a 1 byte field. example: (0)   #encodedas littlendian with parent like XXXXXXXX
#TODO feature: add encodedas json
#TODO fix?: override field from different parent levels
#TODO fix: throw parse error if can't override subtype (overriden field not existing in parent)
#TODO fix: create fails with multi-subtypeof

            
if __name__ == "__main__":
    cli_main()
