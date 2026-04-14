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
	cell.Provide(k8s.NodeResource),

	cell.ProvidePrivate(newLbPinMapEventStream),
	cell.Provide(newLbPinMapEventObservable),
	cell.Invoke(registerPinningManager),
)
