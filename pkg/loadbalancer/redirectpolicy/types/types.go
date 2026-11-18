// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// LRPServiceNameSuffix is the suffix to append to the local redirect policy
// name to construct the pseudo-service name to which the matched pods are associated
// as backends. ':' is used as separator as that is not an allowed character in k8s.
const LRPServiceNameSuffix = ":local-redirect"
