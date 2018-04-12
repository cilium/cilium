#!/bin/bash

cd ${WORKSPACE}/test

TEST_RESULTS="test_results"
ARCHIVE_NAME="${TEST_RESULTS}_${JOB_BASE_NAME}_${BUILD_NUMBER}.zip"
if [ -n "$1" ]
then
    ARCHIVE_NAME="${1}_${TEST_RESULTS}_${JOB_BASE_NAME}_${BUILD_NUMBER}.zip"
    echo $ARCHIVE_NAME
fi

zip -r ${ARCHIVE_NAME} ${TEST_RESULTS}
mv ${ARCHIVE_NAME} ../
rm -rf ./${TEST_RESULTS}
