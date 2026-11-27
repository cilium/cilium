// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qos

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/qos/config"
)

// Cell provides the agent side of the QoS API. The operator side lives in
// operator/pkg/qos.
var Cell = cell.Module(
	"qos",
	"Network Quality of Service",

	cell.Config(config.DefaultConfig),

	// Wait for the QoS CRDs when QoS is enabled.
	cell.Provide(qosCRDSyncResourceNames),
)

// qosCRDSyncResourceNames makes the agent wait for the QoS CRDs to be
// available when QoS is enabled.
func qosCRDSyncResourceNames(cfg config.Config) k8sSynced.CRDSyncResourceNamesOut {
	if !cfg.EnableQoS {
		return k8sSynced.CRDSyncResourceNamesOut{}
	}
	return k8sSynced.NewCRDSyncResourceNamesOut(
		k8sSynced.CRDResourceName(v2alpha1.CQMName),
		k8sSynced.CRDResourceName(v2alpha1.CQCName),
		k8sSynced.CRDResourceName(v2alpha1.CQPName),
	)
}
