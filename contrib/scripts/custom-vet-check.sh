#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# "customvet" is a custom go vet tool that can be found at
# https://github.com/cilium/customvet
# It performs custom static analysis checks checks for the
# cilium repository.
"$GO" run github.com/cilium/customvet -timeafter.ignore inctimer -readall.ignore safeio ./...
