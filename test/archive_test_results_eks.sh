#!/usr/bin/env bash

set -x

cd ${TESTDIR}

TEST_RESULTS="test_results"
ARCHIVE_NAME="${TEST_RESULTS}_${JOB_BASE_NAME}_${BUILD_NUMBER}_${STAGE_NAME/ /}.zip"

find $TEST_RESULTS/  -name "*.zip" | xargs -I '{}' mv '{}' ../

zip -qr ${ARCHIVE_NAME} ${TEST_RESULTS}
mv ${ARCHIVE_NAME} ../

rm -rf ./${TEST_RESULTS}
