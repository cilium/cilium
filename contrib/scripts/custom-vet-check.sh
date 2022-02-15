#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# "customvet" is a custom go vet tool that can be found at
# https://github.com/cilium/customvet
# It performs custom static analysis checks checks for the
# cilium repository.
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
TOOLS=${SCRIPTPATH}/../../tools
${TOOLS}/customvet -timeafter.ignore inctimer ./...
