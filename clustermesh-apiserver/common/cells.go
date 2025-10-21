// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"errors"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/clustermesh-apiserver/health"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

var Cell = cell.Module(
	"clustermesh-common",
	"Common Cilium ClusterMesh modules",

	cell.Config(option.DefaultLegacyClusterMeshConfig),
	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Invoke(cmtypes.RegisterClusterInfoValidator),

	cmmetrics.Cell,
	health.HealthAPIServerCell,

	controller.Cell,
	kvstore.Cell(kvstore.EtcdBackendName),
	cell.Provide(func(ss syncstate.SyncState) kvstore.ExtraOptions {
		return kvstore.ExtraOptions{
			BootstrapComplete: ss.WaitChannel(),
		}
	}),
	store.Cell,

	cell.Invoke(func(client kvstore.Client) error {
		// Both clustermesh-apiserver and kvstoremesh depend on the etcd client.
		if !client.IsEnabled() {
			return errors.New("KVStore client not configured, cannot continue")
		}

		return nil
	}),

	// Shell for inspecting the clustermesh-apiserver/kvstoremesh.
	// Listens on the 'shell.sock' UNIX socket.
	shell.ServerCell(defaults.ShellSockPath),
)
