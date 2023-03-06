// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/auth/monitor"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
)

// Cell provides the auth.Manager which is responsible for request authentication.
// It does this, by implementing consumer.MonitorConsumer and reacting upon
// monitor.DropNotify events with reason flow.DropReason_AUTH_REQUIRED.
// The actual authentication gets performed by an auth handler which is
// responsible for the configured auth type on the corresponding policy.
var Cell = cell.Module(
	"auth-manager",
	"Authenticates requests as demanded by policy",

	// The manager is the main entry point which gets registered to the agent monitor and receives auth requests.
	cell.Provide(newManager),
	cell.ProvidePrivate(
		// Null auth handler provides support for auth type "null" - which always succeeds.
		newNullAuthHandler,
		// CT map authenticator provides support to write authentication information into the eBPF conntrack map
		newCtMapAuthenticator,
	),
	cell.Config(config{MeshAuthMonitorQueueSize: 1024}),
)

type config struct {
	MeshAuthMonitorQueueSize int
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Int("mesh-auth-monitor-queue-size", r.MeshAuthMonitorQueueSize, "Queue size for the auth monitor")
}

type authManagerParams struct {
	cell.In

	Lifecycle             hive.Lifecycle
	Config                config
	AuthHandlers          []authHandler `group:"authHandlers"`
	DatapathAuthenticator datapathAuthenticator
}

type Manager interface {
	consumer.MonitorConsumer
	SetIPCache(*ipcache.IPCache)
}

func newManager(params authManagerParams) (Manager, error) {
	mgr, err := newAuthManager(params.AuthHandlers, params.DatapathAuthenticator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	dropMonitor := monitor.New(mgr, params.Config.MeshAuthMonitorQueueSize)

	params.Lifecycle.Append(hive.Hook{
		OnStart: dropMonitor.OnStart,
		OnStop:  dropMonitor.OnStop,
	})

	return &manager{
		monitorConsumer: dropMonitor,
		manager:         mgr,
	}, nil
}

type manager struct {
	monitorConsumer consumer.MonitorConsumer
	manager         *authManager
}

func (r *manager) SetIPCache(ipCache *ipcache.IPCache) {
	r.manager.ipCache = ipCache
}

func (r *manager) NotifyAgentEvent(typ int, message interface{}) {
	r.monitorConsumer.NotifyAgentEvent(typ, message)
}

func (r *manager) NotifyPerfEvent(data []byte, cpu int) {
	r.monitorConsumer.NotifyPerfEvent(data, cpu)
}

func (r *manager) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	r.monitorConsumer.NotifyPerfEventLost(numLostEvents, cpu)
}

type authHandlerResult struct {
	cell.Out

	AuthHandler authHandler `group:"authHandlers"`
}

func newNullAuthHandler() authHandlerResult {
	return authHandlerResult{
		AuthHandler: &nullAuthHandler{},
	}
}
