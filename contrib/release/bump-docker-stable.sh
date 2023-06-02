#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh

CONTAINER_ENGINE=${CONTAINER_ENGINE:-docker}
IMAGES=(cilium hubble-relay docker-plugin operator operator-generic operator-aws operator-azure)

usage() {
    logecho "usage: $0 <VERSION>"
    logecho "VERSION    Version to bump stable tags to"
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

    echo -n "Set stable docker tags to $version"
    if ! common::askyorn ; then
        common::exit 0 "Aborting stable tag bump."
    fi

    for image in ${IMAGES[@]}; do
        $CONTAINER_ENGINE pull docker.io/cilium/$image:$version
    done

    for image in ${IMAGES[@]}; do
        $CONTAINER_ENGINE tag docker.io/cilium/$image:$version docker.io/cilium/$image:stable
        $CONTAINER_ENGINE push docker.io/cilium/$image:stable
    done
}

main "$@"
