# Identified Problems and Flaws

This file tracks technical debt, bugs, and inconsistencies identified during cross-validation with standard tools like `tshark`.

## 1. Decoding & Formatters
- [x] **IP Address Formatting**: In IPv4, IPv6, ARP, and VLAN layers, IP addresses are now correctly formatted as dotted-quad or colon-separated notation.
- [x] **MAC Address Inconsistency**: ARP layer MACs are now correctly formatted and uppercase hex is used consistently.
- [x] **IPv6 Truncation**: Default field bytes limit increased to 32, and formatted identifiers are exempt from truncation if reasonably short.
- [x] **DNS Name Display**: `dns_name` fields now show as human-readable domain strings (e.g., `google.com`).

## 2. Protocol Identification & Dispatch
- [x] **UDP Chaining (DNS Response)**: `udp.coco` now dispatches to `dns_message` if either `src_port` or `dst_port` is 53.
- **ICMPv6 Dissection Depth**: Identification stops at `icmp_type` and `code`. Specialized bodies for Neighbor Solicitation/Advertisement are currently not dissected.

## 3. Layer Logic & Padding
- **Ethernet Padding Miscalculation**: 
    - In ARP packets, `_pad` fields sometimes contain data that looks like valid headers, suggesting `fill_to: 60` might be over-calculating or triggered incorrectly when layers are nested.
- **FCS False Positives**: In some captures (e.g., VLAN-tagged ARP), the tool incorrectly identifies trailing bytes as an `fcs` field and additional padding, which doesn't align with ground-truth captures.

## 4. CLI & UX
- **Debug Noise**: The CLI prints internal `DEBUG add_nested_dict` logs to stdout, which clutters the tree output.
- [x] **Automatic Field Truncation**: Fixed by increasing default limit and adding exemptions for formatted fields.
- **Formatter Inconsistency**: There is significant code duplication between the various output formats (`tree`, `porcelain`, `compact`, etc.). Most formatting logic (truncation, pointer resolution, flattening) should be shared.
- [x] **Missing JSON Format**: The `--format=json` option is now fully implemented and hooked up to the CLI.

## 5. Protocol Spec Incompleteness
- **TCP Options**: Many TCP options are still shown as `rest` raw bytes instead of fully dissected structures.
- [x] **DNS RR Data**: Resource record data (`rdata`) now has structure overrides for A, AAAA, MX, CNAME, NS, and PTR types.
