#!/bin/bash

function check_img_list {
  local imgs=$@
  for img in $imgs ; do 
    #fmt_img=$img
    fmt_img=$(echo $img | sed -e 's/.*docker.io\///g' | sed -e 's/library\///g')
    #echo "checking if $img is cached..."
    IMG_EXISTS=$(docker images $fmt_img | wc -l) 
    if [[ "$IMG_EXISTS" != "2" ]] ; then
      #echo "*******************************"
      echo -e "not cached in VM: \t$img"
      echo -e "pulling: \t\t$img"
      docker pull $img --quiet &
      #echo "*******************************"
    else
      echo -e "already cached: \t$img"
    fi
  done
}

function test_images {
  echo "Downloading all container images needed for tests"
  DOCKER_IMAGES=$(grep -rI "docker.io/.*/.*:.*" test/ | sed -e 's/\"//g' | grep -v "{}"  | sed -e 's/.*docker.io/docker.io/g' |  sort | uniq)
  QUAY_IMAGES=$(grep -rI "quay.io/.*/.*:.*" test/ | sed -e 's/\"//g' | grep -v "{}" | sed -e 's/.*quay.io/quay.io/g'  | sort | uniq)

  check_img_list $DOCKER_IMAGES
  check_img_list $QUAY_IMAGES

  for p in `jobs -p`; do
    wait $p
  done
}

function cilium_images {
  echo "Downloading all images needed to build cilium"
  CILIUM_DOCKERFILES="./Dockerfile ./cilium-operator.Dockerfile ./Dockerfile.builder"
  CILIUM_IMGS=$(grep -rI "quay.io/.*/.*:.*" $CILIUM_DOCKERFILES | sed -e 's/\"//g' | grep -v "{}" | sed -e 's/.*quay.io/quay.io/g' | sed -e 's/ as.*//g'  | sort | uniq)

  check_img_list $CILIUM_IMGS
  for p in `jobs -p`; do
    wait $p
  done
}

if [ $# -lt 2 ]; then
  echo "Usage: $0 <function-name> <path to root of cilium repository>"
  exit 1
fi

OLDDIR=$PWD
cd $2

trap "cd $OLDDIR" EXIT

$1
