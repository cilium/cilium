#!/usr/bin/env bash

function get_local_dir() {
   cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd
}

versions=($(cat < "$(get_local_dir)/k8s_versions.txt" | grep -Eo '^[0-9]\.[0-9]{2}' | tr "\n" " "))

cilium_version=${cilium_version:-$(cat < "$(get_local_dir)/../../stable.txt")}
cilium_container_repo=${cilium_container_repo:-"quay.io/cilium"}
cilium_container_image=${cilium_container_image:-"cilium"}
cilium_operator_container_image=${cilium_operator_container_image:-"operator-generic"}

function pre-pull-images() {
    docker pull "${cilium_container_repo}/${cilium_container_image}:${cilium_version}"
    docker pull "${cilium_container_repo}/${cilium_operator_container_image}:${cilium_version}"
}

for arg in "$@"
do
    case $arg in
        "--pre-pull-images" )
            pre-pull-images
        ;;
   esac
done
