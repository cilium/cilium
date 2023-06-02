#!/usr/bin/env bash

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
      case $K8S_VERSION in
        "1.16"|"1.17"|"1.18"|"1.19"|"1.20"|"1.21"|"1.22"|"1.23")
          docker pull $img --quiet &
        ;;
        *)
          sudo ctr images pull "${img}" >/dev/null &
        ;;
      esac
      #echo "*******************************"
    else
      echo -e "already cached: \t$img"
    fi
  done
}

function test_images {
  echo "Downloading all container images needed for tests"
  # Filter out just image names.
  # grep's -I ignores binary files, -no-filename doesn't print filenames
  # sed's -n does not print non-matching lines and the `#p` prints only
  # matching groups. `#` is used as the sed delimiter to avoid escaping `/` in
  # the regex.
  DOCKER_IMAGES=$(grep -rI --no-filename "docker.io" . | sed -nEe 's#.*(docker.io/[-_a-zA-Z0-9]+/[-_a-zA-Z0-9]+:[-_.a-zA-Z0-9]+).*#\1#p' | sort | uniq)
  QUAY_IMAGES=$(grep -rI --no-filename "quay.io" .     | sed -nEe   's#.*(quay.io/[-_a-zA-Z0-9]+/[-_a-zA-Z0-9]+:[-_.a-zA-Z0-9]+).*#\1#p' | sort | uniq)

  check_img_list $DOCKER_IMAGES
  check_img_list $QUAY_IMAGES

  for p in `jobs -p`; do
    wait $p
  done
}

function cilium_images {
  echo "Downloading all images needed to build cilium"
  CILIUM_IMGS=$(grep -rI --no-filename "quay.io" images/*/Dockerfile | sed -nEe 's#.*(quay.io/[-_a-zA-Z0-9]+/[-_a-zA-Z0-9]+:[-_.a-zA-Z0-9]+)[^-_.a-zA-Z0-9].*#\1#p' | sort | uniq)

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
