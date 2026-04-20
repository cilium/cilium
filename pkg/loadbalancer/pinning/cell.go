// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"lb-service-node-pinning",
	"Pins a service to a node according to specified rules",

	cell.ProvidePrivate(k8s.NodeResource),
	cell.ProvidePrivate(k8s.ServiceResource),
	cell.ProvidePrivate(NewLbPinMapEventStream),
	cell.Provide(NewLbPinMapEventObservable),
	cell.Invoke(registerPinningManager),
)
