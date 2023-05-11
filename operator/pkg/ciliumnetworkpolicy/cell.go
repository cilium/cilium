// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumnetworkpolicy

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

var Cell = cell.Module(
	"cnp-watcher",
	"CiliumNetworkPolicy watcher",

	cell.Config(CNPWatcherOptions{
		MaxRetries: 10,
	}),

	// Provide LBIPAM so instances of it can be used while testing
	cell.Provide(newCNPWatcher),
	// Invoke an empty function which takes an CNPWatcher to force its construction.
	cell.Invoke(func(*CNPWatcher) {}),
)

type CNPWatcherParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Clientset k8sClient.Clientset
}
