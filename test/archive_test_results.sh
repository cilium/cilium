#!/bin/bash
 
cd ${WORKSPACE}/test

TEST_RESULTS="test_results"
ARCHIVE_NAME="${TEST_RESULTS}_${JOB_BASE_NAME}_${BUILD_NUMBER}.tar"

tar czf ${ARCHIVE_NAME} ${TEST_RESULTS}
mv ${ARCHIVE_NAME} ../
rm -rf ./${TEST_RESULTS}
