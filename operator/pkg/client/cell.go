// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/hive/cell"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

var Cell = cell.Module(
	"operator-k8s-client-builder",
	"Operator Kubernetes Client Builder",

	k8sClient.ClientBuilderCell,
	cell.Provide(func(f k8sClient.ClientBuilderFunc) (k8sClient.Clientset, error) { return f("cilium-operator") }),
)
