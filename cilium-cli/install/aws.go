// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

const (
	AwsNodeDaemonSetName              = "aws-node"
	AwsNodeDaemonSetNamespace         = "kube-system"
	AwsNodeDaemonSetNodeSelectorKey   = "io.cilium/aws-node-enabled"
	AwsNodeDaemonSetNodeSelectorValue = "true"
)
