# Golden Tests

Regression tests that ensure protococo's behavior doesn't change unexpectedly.

## Usage

```bash
# Run all tests
./tests/run_golden_tests.sh

# Verbose mode (shows commands and output)
./tests/run_golden_tests.sh -v
```

## Structure

```
tests/
├── run_golden_tests.sh       # Test runner
├── add_golden_test.sh         # Helper to add new tests
├── fixtures/                  # .coco protocol definitions
└── golden/                    # Test files
    └── <category>/
        ├── test_name.test     # Test definition
        └── fixtures/
            └── test_name.expected  # Expected output
```

## Adding Tests

```bash
./tests/add_golden_test.sh <category> <name> "<command>"
```

Or manually:
1. Create `.test` file defining `COMMAND`, `EXPECTED_EXIT`, `EXPECTED_OUTPUT`
2. Run command and save output to `.expected` file
3. Run `./tests/run_golden_tests.sh` to verify
