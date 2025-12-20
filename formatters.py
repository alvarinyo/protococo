"""
Protococo Display Formatters v1.0

Registry of display formatters for field values.
Formatters transform raw hex values into human-readable strings.

Built-in formatters:
- ipv4: Format as IPv4 address (4 bytes -> "192.168.1.1")
- ipv6: Format as IPv6 address (16 bytes)
- mac: Format as MAC address (6 bytes -> "AA:BB:CC:DD:EE:FF")
- hex: Format as hex string with 0x prefix
- decimal: Format as decimal integer
- binary: Format as binary string
- ascii: Format as ASCII string

Future: Python plugin system will load custom formatters from a directory.
"""

from typing import Callable

# Type for formatter functions: (hex_string, byte_count, endian) -> formatted_string
FormatterFunc = Callable[[str, int, str], str]

# Registry of formatters
_formatters: dict[str, FormatterFunc] = {}


def register(name: str):
    """Decorator to register a formatter."""
    def decorator(func: FormatterFunc) -> FormatterFunc:
        _formatters[name] = func
        return func
    return decorator


def get_formatter(name: str) -> FormatterFunc | None:
    """Get a formatter by name."""
    return _formatters.get(name)


def format_value(name: str, hex_value: str, endian: str = "be") -> str | None:
    """Format a hex value using a named formatter.

    Args:
        name: Formatter name (e.g., "ipv4", "mac")
        hex_value: Hex string to format
        endian: Endianness ("be" or "le")

    Returns:
        Formatted string, or None if formatter not found
    """
    formatter = get_formatter(name)
    if formatter is None:
        return None
    byte_count = len(hex_value) // 2
    return formatter(hex_value, byte_count, endian)


def list_formatters() -> list[str]:
    """List all registered formatter names."""
    return list(_formatters.keys())


# === Built-in Formatters ===

@register("ipv4")
def format_ipv4(hex_value: str, byte_count: int, endian: str) -> str:
    """Format 4 bytes as IPv4 address."""
    if byte_count != 4:
        return hex_value  # Can't format non-4-byte value
    try:
        raw_bytes = bytes.fromhex(hex_value)
        return ".".join(str(b) for b in raw_bytes)
    except ValueError:
        return hex_value


@register("ipv6")
def format_ipv6(hex_value: str, byte_count: int, endian: str) -> str:
    """Format 16 bytes as IPv6 address."""
    if byte_count != 16:
        return hex_value
    try:
        # Group into 2-byte segments
        parts = [hex_value[i:i+4] for i in range(0, 32, 4)]
        # Remove leading zeros in each part
        parts = [p.lstrip('0') or '0' for p in parts]
        return ":".join(parts)
    except ValueError:
        return hex_value


@register("mac")
def format_mac(hex_value: str, byte_count: int, endian: str) -> str:
    """Format 6 bytes as MAC address."""
    if byte_count != 6:
        return hex_value
    try:
        # Split into 2-char groups
        parts = [hex_value[i:i+2].upper() for i in range(0, 12, 2)]
        return ":".join(parts)
    except ValueError:
        return hex_value


@register("hex")
def format_hex(hex_value: str, byte_count: int, endian: str) -> str:
    """Format as hex with 0x prefix."""
    return f"0x{hex_value.upper()}"


@register("decimal")
def format_decimal(hex_value: str, byte_count: int, endian: str) -> str:
    """Format as decimal integer."""
    try:
        raw_bytes = bytes.fromhex(hex_value)
        byteorder = 'little' if endian == 'le' else 'big'
        value = int.from_bytes(raw_bytes, byteorder=byteorder)
        return str(value)
    except ValueError:
        return hex_value


@register("binary")
def format_binary(hex_value: str, byte_count: int, endian: str) -> str:
    """Format as binary string."""
    try:
        value = int(hex_value, 16)
        return f"0b{value:0{byte_count * 8}b}"
    except ValueError:
        return hex_value


@register("ascii")
def format_ascii(hex_value: str, byte_count: int, endian: str) -> str:
    """Format as ASCII string with raw hex: '48656c6c6f (Hello)'."""
    try:
        raw_bytes = bytes.fromhex(hex_value)
        # Replace non-printable characters
        result = ""
        for b in raw_bytes:
            if 32 <= b < 127:
                result += chr(b)
            else:
                result += "."
        return f'{hex_value} ("{result}")'
    except ValueError:
        return hex_value


# Well-known port names (common ports)
_WELL_KNOWN_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9092: "kafka",
    27017: "mongodb",
}


@register("port")
def format_port(hex_value: str, byte_count: int, endian: str) -> str:
    """Format as network port with service name: '443 (https)'."""
    if byte_count != 2:
        return hex_value
    try:
        raw_bytes = bytes.fromhex(hex_value)
        # Ports are always big-endian in network protocols
        port_num = int.from_bytes(raw_bytes, byteorder='big')
        port_name = _WELL_KNOWN_PORTS.get(port_num)
        if port_name:
            return f"{port_num} ({port_name})"
        return str(port_num)
    except ValueError:
        return hex_value


# Future: Plugin loading
# def load_plugins(plugin_dir: str) -> None:
#     """Load custom formatters from Python files in plugin_dir."""
#     import importlib.util
#     from pathlib import Path
#
#     plugin_path = Path(plugin_dir)
#     for py_file in plugin_path.glob("*.py"):
#         spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
#         module = importlib.util.module_from_spec(spec)
#         spec.loader.exec_module(module)
