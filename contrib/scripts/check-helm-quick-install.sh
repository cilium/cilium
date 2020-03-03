#!/bin/bash

set -e

MAKE=${MAKE:-make}
HELM_BIN=${HELM_BIN:-helm}
HELM_CHART_DIR=./install/kubernetes
OLD_QUICK_INSTALL=${HELM_CHART_DIR}/quick-install.yaml

function check_helm_version() {
    if test -x "$(command -v $HELM_BIN)"; then
        CURRENT_VERSION="$($HELM_BIN version 2>&1 | sed 's/^.*Version:\"v\([0-9]*\.[0-9]*\.[0-9]*\).*$/\1/')"
        if [ "$CURRENT_VERSION" == "$HELM_VERSION" ]; then
            return
        fi

        echo "helm version ${CURRENT_VERSION} is installed, supported helm version is ${HELM_VERSION}"
    else
        echo "helm not found, try installing helm first"
    fi

    exit 1
}

check_helm_version

TMP_FILE=$(mktemp)
trap 'rm $TMP_FILE' EXIT INT TERM

${MAKE} QUICK_INSTALL=${TMP_FILE} -C ${HELM_CHART_DIR} quick-install

if ! diff -q ${TMP_FILE} ${OLD_QUICK_INSTALL}; then
    echo "diff: $(diff ${TMP_FILE} ${OLD_QUICK_INSTALL})"
    echo "Please rerun 'make -C install/kubernetes quick-install' and commit your changes."
    exit 1
fi
