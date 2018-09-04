#!/bin/bash

# This script checks Jenkins master Jobs and validated that the failed jobs has
# been already triaged and upstream issue has been created if it's needed.
# To clean the list of Jenkins builds, build description needs to be updated with a comment.

# allow users to specify SINCE as seconds since epoch
YESTERDAY=$(date -d -1day)
SINCE=${SINCE:-$YESTERDAY}
# ensure SINCE is the correct length
SINCE=$(date -d "$SINCE" +%s%N  | cut -b1-13)

TAB="   "
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
BLUE=$(tput setaf 4)

get_job_data () {
    local JOB=$1
    local FILTER="?tree=builds[fullDisplayName,id,number,timestamp,result,description,result]"
    local TEST_RESULT="/testReport/junit/api/xml?xpath=//case[status%20=%20%22REGRESSION%22]/name&wrapper=true"

    NO_TRIAGED_FAILURES=$(curl -s "${JOB}api/json${FILTER}" --globoff | jq -r '.builds[] | select ( .timestamp  > '$SINCE' and .result == "FAILURE" and .description == null) | .id')
    for build in $NO_TRIAGED_FAILURES;
    do
        echo "${BOLD}BUILD ID: ${build}${NORMAL}"
        echo -e "${TAB}${BOLD}${BLUE}URL${NORMAL}: ${JOB}${build}"
        RESULTS=$(curl -s "${JOB}/${build}/${TEST_RESULT}" --globoff)
        echo -e "${TAB}${BOLD}${BLUE}TEST_FAILURE${NORMAL}: \n \t${RESULTS}"
    done
}

get_job_data "https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/master/"
get_job_data "https://jenkins.cilium.io/job/Ginkgo-CI-Tests-Pipeline/"
get_job_data "https://jenkins.cilium.io/job/Cilium-Master-Nightly-Tests-All/"
get_job_data "https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/v1.0/"
