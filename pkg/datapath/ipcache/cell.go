// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
)

// Cell is a cell that provides and registers the listener which synchronizes
// the userspace ipcache with the corresponding BPF map.
var Cell = cell.Module(
	"ipcache-bpf-listener",
	"IPCache BPF Listener",

	cell.Provide(NewListener),
	cell.ProvidePrivate(
		func(m *ipcacheMap.Map) Map { return m },
		func(agent monitorAgent.Agent) monitorNotify { return agent },
	),

	cell.Invoke(func(lifecycle cell.Lifecycle, listener *BPFListener, ipc *ipcache.IPCache) {
		// AddListener synchronously replays the existing IPCache entries to the listener, which
		// writes them to the BPF map. The dependency on the listener, and thus on the map, and the
		// registration happening in the OnStart hook, guarantee that the replay runs after the
		// inner BPF map is initialized.
		lifecycle.Append(cell.Hook{OnStart: func(cell.HookContext) error {
			ipc.AddListener(listener)
			return nil
		}})
	}),
)
