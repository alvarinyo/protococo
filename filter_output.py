#!/usr/bin/env python3
"""
Interactive TUI for filtering and expanding protococo output.
Usage: protococo find ... | python3 filter_output.py
       python3 filter_output.py < output.txt
"""

import sys
import re
import logging
import argparse
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Collapsible, Footer, Static
from textual.binding import Binding
from textual.events import Key

# Set up logging
logging.basicConfig(
    filename='/tmp/filter_output.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def strip_ansi(text):
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def parse_sections(text, pattern=None):
    """Parse input into (title, content) sections.

    Args:
        text: Input text to parse
        pattern: Regex pattern to match section titles. If the pattern has a capture group,
                 it will be used as the title. Otherwise, the full match is used.
                 Default: r'^\[.*\]$' (matches lines like [section_name])
    """
    if pattern is None:
        pattern = r'^\[.*\]$'

    sections = []
    lines = text.strip().split('\n')

    current_title = None
    current_content = []

    # Compile the regex pattern
    try:
        title_regex = re.compile(pattern)
    except re.error as e:
        logging.error(f"Invalid regex pattern: {e}")
        raise ValueError(f"Invalid regex pattern: {e}")

    for line in lines:
        # Strip ANSI codes to check if it's a title
        clean_line = strip_ansi(line).strip()

        # Check if line matches the title pattern
        match = title_regex.match(clean_line)
        if match:
            # Save previous section if exists
            if current_title is not None:
                sections.append((current_title, '\n'.join(current_content)))

            # Extract title from capture group if it exists, otherwise use full match
            if match.groups():
                current_title = match.group(1)
            else:
                current_title = match.group(0)

            current_content = []
        else:
            # Add to current content (keep ANSI codes for display)
            if current_title is not None and line.strip():
                current_content.append(line)

    # Don't forget the last section
    if current_title is not None:
        sections.append((current_title, '\n'.join(current_content)))

    return sections


class ProtocolViewer(App):
    """Interactive viewer for protococo output."""

    CSS = """
    Collapsible {
        height: auto;
        border: none;
        padding: 0;
        margin: 0;
    }

    Collapsible > CollapsibleTitle {
        padding: 0 1;
        height: 1;
        background: $boost;
    }

    Collapsible > Contents {
        padding: 0 2;
        height: auto;
        overflow-x: auto;
        scrollbar-size: 1 1;
    }

    .content {
        width: auto;
        height: auto;
        content-align: left top;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "collapse_or_expand(False)", "Expand All"),
        Binding("c", "collapse_or_expand(True)", "Collapse All"),
        Binding("r", "refresh", "Refresh"),
        Binding("j", "focus_next", "Down", show=False),
        Binding("k", "focus_previous", "Up", show=False),
    ]

    def __init__(self, sections, filename=None, pattern=None):
        super().__init__()
        self.sections = sections
        self.filename = filename
        self.pattern = pattern
        logging.info(f"ProtocolViewer initialized with {len(sections)} sections")

    def on_mount(self) -> None:
        """Called when app is mounted."""
        logging.info("App mounted successfully")

    def on_key(self, event: Key) -> None:
        """Log all key events."""
        logging.info(f"Key pressed: {event.key!r} (char: {event.character!r})")
        # Don't manually handle keys - let bindings do it
        # Otherwise we get double-triggering

    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        logging.info("Composing UI")
        yield Footer()
        with VerticalScroll(id="main-scroll"):
            for idx, (title, content) in enumerate(self.sections):
                # Create a Rich Text object from ANSI codes with no wrapping
                text = Text.from_ansi(content, no_wrap=True)

                # Create a non-focusable Static for content
                static = Static(text, expand=False, shrink=False, classes="content")
                static.can_focus = False

                collapsible = Collapsible(
                    static,
                    title=title,
                    collapsed=True,
                )
                logging.info(f"Creating collapsible {idx}: {title}")
                yield collapsible

    def action_collapse_or_expand(self, collapse: bool) -> None:
        """Collapse or expand all sections."""
        logging.info(f"action_collapse_or_expand called with collapse={collapse}")
        count = 0
        for child in self.walk_children(Collapsible):
            child.collapsed = collapse
            count += 1
        logging.info(f"Updated {count} collapsible widgets")

    def action_refresh(self) -> None:
        """Refresh the content by re-reading the file."""
        if not self.filename:
            logging.warning("No filename available for refresh")
            return

        logging.info(f"Refreshing from file: {self.filename}")

        try:
            with open(self.filename, 'r') as f:
                input_text = f.read()
            logging.info(f"Re-read {len(input_text)} characters from {self.filename}")

            # Parse new sections with the same pattern
            new_sections = parse_sections(input_text, pattern=self.pattern)
            logging.info(f"Parsed {len(new_sections)} sections")

            if not new_sections:
                logging.warning("No sections found after refresh")
                return

            # Update sections
            self.sections = new_sections

            # Remove all existing collapsibles
            for child in list(self.query(Collapsible)):
                child.remove()

            # Add new collapsibles
            scroll = self.query_one(VerticalScroll)
            for idx, (title, content) in enumerate(self.sections):
                text = Text.from_ansi(content, no_wrap=True)
                static = Static(text, expand=False, shrink=False, classes="content")
                static.can_focus = False

                collapsible = Collapsible(
                    static,
                    title=title,
                    collapsed=True,
                )
                scroll.mount(collapsible)

            logging.info("Refresh complete")

        except Exception as e:
            logging.error(f"Error during refresh: {e}")


def main():
    """Read from a file and launch the TUI."""
    logging.info("=== Starting filter_output.py ===")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Interactive TUI for collapsible structured text output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Default pattern (lines like [section_name])
  python3 filter_output.py output.txt

  # Custom pattern with capture group
  python3 filter_output.py output.txt --pattern '^===\\s+(.*)\\s+===$'
  python3 filter_output.py output.txt --pattern '^##\\s+(.*)$'
  python3 filter_output.py output.txt -p '^---\\s+(.*)\\s+---$'

  # Pattern without capture group (uses full match as title)
  python3 filter_output.py output.txt --pattern '^\\[.*\\]$'

Default pattern: ^\\[.*\\]$
        '''
    )
    parser.add_argument('file', help='Input file to read')
    parser.add_argument(
        '-p', '--pattern',
        help='Regex pattern to match section titles. Use a capture group () to extract the title.',
        default=None
    )

    args = parser.parse_args()
    filename = args.file
    pattern = args.pattern

    logging.info(f"Reading from file: {filename}")
    if pattern:
        logging.info(f"Using custom pattern: {pattern}")
    else:
        logging.info("Using default pattern: ^\\[.*\\]$")

    # Read from file
    try:
        with open(filename, 'r') as f:
            input_text = f.read()
        logging.info(f"Read {len(input_text)} characters from {filename}")
    except FileNotFoundError:
        print(f"Error: {filename} not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    if not input_text.strip():
        print("Error: File is empty", file=sys.stderr)
        sys.exit(1)

    # Parse sections with optional custom pattern
    try:
        sections = parse_sections(input_text, pattern=pattern)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    logging.info(f"Parsed {len(sections)} sections")
    for i, (title, content) in enumerate(sections):
        content_lines = len(content.split('\n'))
        logging.info(f"Section {i}: title='{title}', content_lines={content_lines}")

    if not sections:
        print("No sections found in file", file=sys.stderr)
        sys.exit(1)

    logging.info("Creating and running app")
    app = ProtocolViewer(sections, filename=filename, pattern=pattern)
    app.run()
    logging.info("App exited")


if __name__ == "__main__":
    main()
