#!/bin/bash
# Helper script to add new golden tests easily

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <category> <test_name> <command>"
    echo ""
    echo "Example:"
    echo "  $0 check valid_message 'python3 protococo.py check msg_type HEXDATA --cocofile=tests/fixtures/foo.coco'"
    echo ""
    echo "Categories: check, find, create, json-recipe, tree"
    exit 1
fi

CATEGORY=$1
TEST_NAME=$2
COMMAND=$3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

TEST_DIR="tests/golden/$CATEGORY"
FIXTURES_DIR="$TEST_DIR/fixtures"

# Create directories if they don't exist
mkdir -p "$FIXTURES_DIR"

# Paths
TEST_FILE="$TEST_DIR/${TEST_NAME}.test"
EXPECTED_FILE="$FIXTURES_DIR/${TEST_NAME}.expected"

# Check if test already exists
if [ -f "$TEST_FILE" ]; then
    echo "Error: Test $TEST_FILE already exists"
    exit 1
fi

# Run the command to generate expected output
echo "Running command to generate expected output..."
set +e
eval "$COMMAND" > "$EXPECTED_FILE" 2>&1
EXIT_CODE=$?
set -e

echo "Command exited with code: $EXIT_CODE"

# Create the test file
cat > "$TEST_FILE" <<EOF
#!/bin/bash
# Test: $TEST_NAME

COMMAND="$COMMAND"
EXPECTED_EXIT=$EXIT_CODE
EXPECTED_OUTPUT="$FIXTURES_DIR/${TEST_NAME}.expected"
EOF

echo ""
echo "✓ Created test file: $TEST_FILE"
echo "✓ Created expected output: $EXPECTED_FILE"
echo ""
echo "Review the expected output:"
echo "  cat $EXPECTED_FILE"
echo ""
echo "Run the test:"
echo "  ./tests/run_golden_tests.sh"
echo ""
echo "If the test fails, you may need to adjust EXPECTED_EXIT in $TEST_FILE"
