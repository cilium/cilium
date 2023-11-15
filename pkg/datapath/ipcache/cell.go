// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"github.com/cilium/cilium/pkg/hive/cell"
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
		func() Map { return ipcacheMap.IPCacheMap() },
		func(agent monitorAgent.Agent) monitorNotify { return agent },
	),

	cell.Invoke(func(listener *BPFListener, ipc *ipcache.IPCache) { ipc.AddListener(listener) }),
)
