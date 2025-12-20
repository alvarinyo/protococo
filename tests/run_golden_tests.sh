#!/bin/bash
# Golden/Regression test runner for protococo
# Compares current output against known-good outputs

set -o pipefail

# Parse arguments
VERBOSE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Show protococo commands and output"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

PASSED=0
FAILED=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "Running golden tests..."
if [ "$VERBOSE" = true ]; then
    echo "(verbose mode)"
fi
echo "======================"
echo

# Find all .test files
for test_file in tests/golden/**/*.test; do
    if [ ! -f "$test_file" ]; then
        continue
    fi

    TOTAL=$((TOTAL + 1))

    # Source the test file to get COMMAND, EXPECTED_EXIT, EXPECTED_OUTPUT
    unset COMMAND EXPECTED_EXIT EXPECTED_OUTPUT EXPECTED_STDERR IGNORE_OUTPUT
    source "$test_file"

    # Validate test file
    if [ -z "$COMMAND" ]; then
        echo -e "${RED}✗ INVALID${NC} $test_file - missing COMMAND"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Set defaults
    EXPECTED_EXIT=${EXPECTED_EXIT:-0}
    IGNORE_OUTPUT=${IGNORE_OUTPUT:-false}

    # Extract test description from comment in test file
    test_description=""
    if [ "$VERBOSE" = true ]; then
        # Get the second line which should be a comment describing the test
        test_description=$(sed -n '2p' "$test_file" | sed 's/^# *Test: *//' | sed 's/^# *//')

        if [ -n "$test_description" ]; then
            echo -e "${YELLOW}→${NC} $test_description"
        fi
        echo -e "${CYAN}  Command:${NC} $COMMAND"
    fi

    # Run the command
    set +e
    actual_stdout=$(eval "$COMMAND" 2>/tmp/stderr_$$)
    actual_exit=$?
    set -e
    actual_stderr=$(cat /tmp/stderr_$$)
    rm -f /tmp/stderr_$$

    # Check exit code
    exit_ok=true
    if [ "$actual_exit" != "$EXPECTED_EXIT" ]; then
        exit_ok=false
    fi

    # Check output if not ignored
    output_ok=true
    if [ "$IGNORE_OUTPUT" = "false" ] && [ -n "$EXPECTED_OUTPUT" ]; then
        if [ ! -f "$EXPECTED_OUTPUT" ]; then
            echo -e "${RED}✗ INVALID${NC} $test_file - missing expected output file: $EXPECTED_OUTPUT"
            FAILED=$((FAILED + 1))
            continue
        fi

        # Strip ANSI color codes for comparison
        actual_stdout_clean=$(echo "$actual_stdout" | sed 's/\x1b\[[0-9;]*m//g')
        expected_stdout_clean=$(cat "$EXPECTED_OUTPUT" | sed 's/\x1b\[[0-9;]*m//g')

        if [ "$actual_stdout_clean" != "$expected_stdout_clean" ]; then
            output_ok=false
        fi
    fi

    # Check stderr if specified
    stderr_ok=true
    if [ -n "$EXPECTED_STDERR" ]; then
        if [ ! -f "$EXPECTED_STDERR" ]; then
            echo -e "${RED}✗ INVALID${NC} $test_file - missing expected stderr file: $EXPECTED_STDERR"
            FAILED=$((FAILED + 1))
            continue
        fi

        actual_stderr_clean=$(echo "$actual_stderr" | sed 's/\x1b\[[0-9;]*m//g')
        expected_stderr_clean=$(cat "$EXPECTED_STDERR" | sed 's/\x1b\[[0-9;]*m//g')

        if [ "$actual_stderr_clean" != "$expected_stderr_clean" ]; then
            stderr_ok=false
        fi
    fi

    # Report results
    test_name=$(basename "$test_file" .test)
    test_category=$(basename "$(dirname "$test_file")")

    if [ "$exit_ok" = true ] && [ "$output_ok" = true ] && [ "$stderr_ok" = true ]; then
        echo -e "${GREEN}✓ PASS${NC} $test_category/$test_name"

        if [ "$VERBOSE" = true ]; then
            echo -e "${BLUE}  Exit code:${NC} $actual_exit"
            if [ "$IGNORE_OUTPUT" = "false" ] && [ -n "$actual_stdout" ]; then
                echo -e "${BLUE}  Output:${NC}"
                echo "$actual_stdout" | sed 's/^/    /'
            fi
            echo
        fi

        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} $test_category/$test_name"
        FAILED=$((FAILED + 1))

        if [ "$exit_ok" = false ]; then
            echo "  Exit code: expected $EXPECTED_EXIT, got $actual_exit"
        fi

        if [ "$output_ok" = false ]; then
            echo "  Output differs:"
            diff -u --color=always "$EXPECTED_OUTPUT" <(echo "$actual_stdout_clean") | head -20
        fi

        if [ "$stderr_ok" = false ]; then
            echo "  Stderr differs:"
            diff -u --color=always "$EXPECTED_STDERR" <(echo "$actual_stderr_clean") | head -20
        fi
        echo
    fi
done

echo
echo "======================"
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC} (total: $TOTAL)"

if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
