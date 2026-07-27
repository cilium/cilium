#!/usr/bin/env bash

function get_local_dir() {
   cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd
}

versions=($(cat < "$(get_local_dir)/k8s_versions.txt" | grep -Eo '^[0-9]\.[0-9]{2}' | tr "\n" " "))
k8s_patch_versions=($(cat < "$(get_local_dir)/k8s_versions.txt" | tr "\n" " "))

cilium_version=${cilium_version:-$(cat < "$(get_local_dir)/../../stable.txt")}
cilium_container_repo=${cilium_container_repo:-"quay.io/cilium"}
cilium_container_image=${cilium_container_image:-"cilium"}
cilium_operator_container_image=${cilium_operator_container_image:-"operator-generic"}


function update-kind-config() {
    i=0
    for version in ${versions[*]}; do
       while read file;do
         local file_sha=$(md5sum "${file}")
         sed -i "s+kindest/node:v${version}.*+kindest/node:v${k8s_patch_versions[${i}]}+" "${file}"
         if [ "${file_sha}" != "$(md5sum "${file}")" ]; then
            find "$(dirname $(dirname "${file}"))" -type d -regextype posix-extended -regex ".*/v${version}" | xargs rm -r 2>/dev/null
         fi
       done <<<$(find . -type f -regextype posix-extended -regex ".*/kind-config-${version}.yaml")
       i=$(( i + 1 ))
    done
}

function pre-pull-images() {
    docker pull "${cilium_container_repo}/${cilium_container_image}:${cilium_version}"
    docker pull "${cilium_container_repo}/${cilium_operator_container_image}:${cilium_version}"
}

for arg in "$@"
do
    case $arg in
        "--update-kind-config" )
            update-kind-config
        ;;
        "--pre-pull-images" )
            pre-pull-images
        ;;
   esac
done
