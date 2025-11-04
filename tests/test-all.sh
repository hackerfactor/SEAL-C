#!/bin/bash
# Runs all test scripts in the tests folder.

# Everything is relative to this test directory.
cd $(dirname "$0")

TEST_SCRIPTS=(
  "test-local.sh:Local Signing"
  "test-remote.sh:Remote Signing"
  "test-inline.sh":Inline Signing
  "test-revoke.sh:Revocation"
  "test-manual.sh:Manual"
)

PASSED_TESTS=()
FAILED_TESTS=()
OVERALL_STATUS=0

for test_info in "${TEST_SCRIPTS[@]}"; do
  script="${test_info%%:*}"
  description="${test_info#*:}"
  
  echo "==========================="
  echo "Running ${description} Tests"
  echo "==========================="
  output=$(./"$script" 2>&1)
  status=$?
  if [ $status -ne 0 ]; then
    OVERALL_STATUS=1
    FAILED_TESTS+=("$script")
    echo "ERROR: $script failed."
    echo "------- SCRIPT OUTPUT -------"
    echo "$output"
    echo "-----------------------------"
  else
    PASSED_TESTS+=("$script")
    echo "Completed Successfully"
  fi
  echo ""
done

echo ""
echo "====================="
echo "Test Execution Summary"
echo "====================="
echo "Passed: ${#PASSED_TESTS[@]}"
echo "Failed: ${#FAILED_TESTS[@]}"
if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
  echo "Failed tests: ${FAILED_TESTS[*]}"
fi
echo "====================="

exit $OVERALL_STATUS
