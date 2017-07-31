#!/bin/bash -e 

DEV_DOCKERFILE="$PWD/../contrib/packaging/docker/dockerfiles/Dockerfile.dev"
PROD_DOCKERFILE="$PWD/../contrib/packaging/docker/dockerfiles/Dockerfile.prod"
DEP_DOCKERFILE="$PWD//../contrib/packaging/docker/dockerfiles/Dockerfile.deps"
DOCKERFILE_SCRIPT="$PWD/../contrib/packaging/docker/build_dockerfile.sh"

function cleanup {
  rm ./Dockerfile.dev.tmpgen || true
  rm Dockerfile.prod.tmpgen || true
  rm Dockerfile.deps.tmpgen || true
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
    echo "$FILE1 differs from $FILE2; please rebuild the corresponding Dockerfile and try again"
    echo "diff: $diff"
    exit 1
  else 
    echo "$FILE1 does not differ from $FILE2; OK"
  fi 
}

trap cleanup EXIT

# Generate each separate Dockerfile.
${DOCKERFILE_SCRIPT} build_dockerfile_dev && mv Dockerfile Dockerfile.dev.tmpgen
${DOCKERFILE_SCRIPT} build_dockerfile_prod && mv Dockerfile Dockerfile.prod.tmpgen
${DOCKERFILE_SCRIPT} build_dockerfile_dependencies && mv Dockerfile Dockerfile.deps.tmpgen

# Check if the generated Dockerfiles differ from those that are already in the repo.
error_if_files_diff ${DEV_DOCKERFILE} ./Dockerfile.dev.tmpgen
error_if_files_diff ${PROD_DOCKERFILE} ./Dockerfile.prod.tmpgen
error_if_files_diff ${DEP_DOCKERFILE} ./Dockerfile.deps.tmpgen


