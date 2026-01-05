// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// TestCell checks that 'Cell' can be instantiated with the defaults and it
// also shows what are the minimal dependencies to it for testing.
func TestCell(t *testing.T) {

	h := hive.New(
		k8sClient.FakeClientCell(),
		daemonk8s.ResourcesCell,
		cell.Config(envoyCfg.SecretSyncConfig{}),
		daemonk8s.TablesCell,
		maglev.Cell,
		node.LocalNodeStoreTestCell,
		metrics.Cell,
		kpr.Cell,
		lbipamconfig.Cell,
		nodeipamconfig.Cell,
		Cell,
		cell.Provide(
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
			source.NewSources,
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{}
			},
		),
	)
	require.NoError(t, h.Populate(hivetest.Logger(t)))
}
