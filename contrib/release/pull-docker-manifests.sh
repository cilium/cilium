#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh

CONTAINER_ENGINE=${CONTAINER_ENGINE:-docker}
IMAGES=(cilium clustermesh-apiserver docker-plugin hubble-relay operator operator-generic operator-aws operator-azure)
REGISTRIES=(docker.io quay.io)

usage() {
    logecho "usage: $0 <VERSION>"
    logecho "VERSION    Target version"
    logecho
    logecho "--help     Print this help message"
}

handle_args() {
    if ! common::argc_validate 2; then
        usage 2>&1
        common::exit 1
    fi

    if [[ "$1" = "--help" ]] || [[ "$1" = "-h" ]]; then
        usage
        common::exit 0
    fi

    if ! echo "$1" | grep -q "[0-9]\+\.[0-9]\+\.[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid VERSION ARG \"$1\"; Expected X.Y.Z"
    fi
}

main() {
    handle_args "$@"

    local ersion="$(echo $1 | sed 's/^v//')"
    local version="v$ersion"

    >&2 echo n "Fetching docker images for $version"
    for image in ${IMAGES[@]}; do
        for registry in ${REGISTRIES[@]}; do
            >&2 $CONTAINER_ENGINE pull $registry/cilium/$image:$version
        done
    done

    >&2 echo "Generating manifest text for $version release notes"
    >&2
    echo "Docker Manifests"
    echo "----------------"
    for image in ${IMAGES[@]}; do
        echo; echo "## $image"; echo
        for registry in ${REGISTRIES[@]}; do
            digest="$(docker inspect $registry/cilium/$image:$version | jq -r '.[0].RepoDigests[0]')"
            if ! echo $digest | grep -q $registry; then
                digest="$registry/$digest"
            fi
            echo "\`$digest\`"
        done
    done
}

main "$@"

