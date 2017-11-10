#!/bin/bash 

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../../tests/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

DEV_DOCKERFILE="$PWD/../Dockerfile.dev"
PROD_DOCKERFILE="$PWD/../Dockerfile"
DEP_DOCKERFILE="$PWD/../Dockerfile.deps"
DOCKERFILE_SCRIPT="$PWD/../contrib/packaging/docker/build_dockerfile.sh"

function cleanup {
  rm ./Dockerfile.dev.tmpgen || true
  rm ./Dockerfile.prod.tmpgen || true
  rm ./Dockerfile.deps.tmpgen || true
}


# error_if_files_diff returns a non-zero return code if the contents of the provided files are different.
# Arguments:
#  FILE1: path to first file
#  FILE2: path to second file
function error_if_files_diff {
  FILE1=$1
  FILE2=$2

  diff="$(diff $FILE1 $FILE2)"


  if [ -n "$diff" ]; then 
    echo "$FILE1 differs from $FILE2; please rebuild the corresponding Dockerfile using the script: contrib/packaging/docker/build_dockerfile.sh"
    echo "diff: $diff"
    exit 1
  else 
    echo "============ $FILE1 does not differ from $FILE2; OK ================="
  fi 
}

trap cleanup EXIT

# Generate each separate Dockerfile.
${DOCKERFILE_SCRIPT} build_dockerfile_dev && mv ${PWD}/../contrib/packaging/docker/Dockerfile Dockerfile.dev.tmpgen
${DOCKERFILE_SCRIPT} build_dockerfile_prod && mv ${PWD}/../contrib/packaging/docker/Dockerfile Dockerfile.prod.tmpgen
${DOCKERFILE_SCRIPT} build_dockerfile_dependencies && mv ${PWD}/../contrib/packaging/docker/Dockerfile Dockerfile.deps.tmpgen

# Check if the generated Dockerfiles differ from those that are already in the repo.
error_if_files_diff ${DEV_DOCKERFILE} ./Dockerfile.dev.tmpgen
error_if_files_diff ${PROD_DOCKERFILE} ./Dockerfile.prod.tmpgen
error_if_files_diff ${DEP_DOCKERFILE} ./Dockerfile.deps.tmpgen
