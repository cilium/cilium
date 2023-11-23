// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import "github.com/cilium/cilium/pkg/option"

var Config = &option.DaemonConfig{
	K8sNamespace:             "kube-system",
	RoutingMode:              option.RoutingModeTunnel,
	EnableRemoteNodeIdentity: true,
	EnableIPSec:              true,
	EncryptNode:              true,
	RoutingMode:              option.RoutingModeNative,
	EnableIPv4Masquerade:     true,
}
