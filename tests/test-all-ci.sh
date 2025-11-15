#!/bin/bash
# Runs all test scripts in the tests folder.

readonly CI_STARTAT=$SECONDS

# Everything is relative to this test directory.
cd $(dirname "$0")

MISSING_CONFIG=false

if [[ -n ${XDG_CONFIG_HOME} && -f "${XDG_CONFIG_HOME}/seal/config" ]]; then
	echo "*** Using configuration file in ${XDG_CONFIG_HOME} for tests"
elif [[ -f "${HOME}/.config/seal/config" ]]; then
	echo "*** Using configuration file for tests"
elif [[ -n "${SIGNMYDATA_APIKEY}" && -n "${SIGNMYDATA_ID}" ]]; then
	echo "*** Building configuration file with environment data"
	mkdir -p "${HOME}/.config/seal"
	cp config.sample "${HOME}/.config/seal/config"
	echo "apikey=${SIGNMYDATA_APIKEY}" >> "${HOME}/.config/seal/config"
	echo "id=${SIGNMYDATA_ID}" >> "${HOME}/.config/seal/config"
else
	MISSING_CONFIG=true
fi

if [[ "$MISSING_CONFIG" == true ]]; then
	echo "***************************************"
	echo "Missing configuration, local tests only"
	echo "***************************************"
	readonly TEST_SCRIPTS=(
		"test-local.sh:Local Signing"
		"test-inline.sh:Inline Signing"
		"test-revoke.sh:Revocation"
	)
else
	readonly TEST_SCRIPTS=(
		"test-local.sh:Local Signing"
		"test-remote.sh:Remote Signing"
		"test-inline.sh:Inline Signing"
		"test-revoke.sh:Revocation"
		"test-manual.sh:Manual"
	)
fi

PASSED_TESTS=()
FAILED_TESTS=()
OVERALL_STATUS=0

for test_info in "${TEST_SCRIPTS[@]}"; do
  script="${test_info%%:*}"
  description="${test_info#*:}"
  
  TEST_STARTAT=$SECONDS
  echo "==========================="
  echo "Running ${description} Tests"
  echo "==========================="
  output=$(./"$script" 2>&1)
  status=$?
  if [ $status -ne 0 ]; then
    OVERALL_STATUS=1
    FAILED_TESTS+=("$script")
    echo "ERROR: $script failed in $((SECONDS - TEST_STARTAT)) seconds."
    echo "------- SCRIPT OUTPUT -------"
    echo "$output"
    echo "-----------------------------"
  else
    PASSED_TESTS+=("$script")
    echo "Completed Successfully in $((SECONDS - TEST_STARTAT)) seconds"
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
echo "Total elapsed: $((SECONDS - CI_STARTAT)) seconds"
echo "====================="

exit $OVERALL_STATUS
