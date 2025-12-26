# Protococo Manifesto: Protocol-as-Code

**Protococo** is a Protocol-as-Code (PAC) experiment seeking to eliminate the gap between protocol design and implementation. Its core vision is that protocol specifications should be **unambiguous, machine-readable, and executable**—aspiring to replace natural language documentation with a single, declarative source of truth.

## The Vision: Protocol Definition = Protocol Implementation

*   **The Spec IS the Toolchain**: A `.coco` file is not just documentation; it is an executable specification. Protococo aims to automatically handle parsing, validation, and tool generation from a single source.
*   **Declarative over Imperative**: Instead of manually tracking offsets and bit-masks in code, you describe *what* the protocol looks like. The engine seeks to handle the *how* of the binary arithmetic.
*   **Single Source of Truth**: By unifying the definition and implementation, the project aspires to prevent the "drift" and interoperability bugs common in traditional protocol engineering.

## The Toolset: Universal Binary Analysis

Protococo seeks to transform these declarative specs into a multi-purpose CLI toolchain:

*   **Identify (`find`)**: Automatically detects and extracts full protocol stacks from raw hex (e.g., identifying a nested `[ethernet:vlan:ipv4:tcp]` chain).
*   **Validate (`check`)**: Performs strict bit-level validation of messages, providing human-readable, color-coded tree visualizations of field compliance.
*   **Create (`create` / `json-recipe`)**: Generates valid binary messages from high-level field values or JSON templates.
*   **Integrate (`wireshark`)**: Generates production-ready Lua dissectors for Wireshark, allowing your custom `.coco` specs to power live traffic analysis.

## The DSL: Power & Expressiveness

The `.coco` language is built to handle the real-world complexity of the Internet stack (Ethernet, IP, TCP):

*   **Polymorphic Dispatch**: Uses enums and **pattern matching** to handle dynamic payloads based on discriminators (like EtherType or IP Protocol).
*   **Bit-Level Precision**: Supports nested **bitfields** and multi-byte packed flags (e.g., the complex TCP header).
*   **Dynamic Logic**: Handles variable-length fields using **computed size expressions** (e.g., `payload[total_length - 20]`).
*   **Human-Friendly Display**: Specialized formatters translate raw bytes into semantic values like IP addresses, MACs, and Port numbers without losing raw precision.

---

**In short: Protococo aspires to turn protocol specifications into executable reality, aiming to replace hundreds of pages of ambiguous text with concise, validated code.**
