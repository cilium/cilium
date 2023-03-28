// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/auth/monitor"
	"github.com/cilium/cilium/pkg/auth/spire"
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

	spire.Cell,

	// The manager is the main entry point which gets registered to the agent monitor and receives auth requests.
	cell.Provide(newManager),
	cell.ProvidePrivate(
		// Null auth handler provides support for auth type "null" - which always succeeds.
		newNullAuthHandler,
		// CT map authenticator provides support to write authentication information into the eBPF conntrack map
		newCtMapAuthenticator,
		// MTLS auth handler provides support for auth type "mtls-*" - which performs mTLS authentication.
		newMTLSAuthHandler,
		// Always fail auth handler provides support for auth type "always-fail" - which always fails.
		newAlwaysFailAuthHandler,
	),
	cell.Config(config{MeshAuthMonitorQueueSize: 1024}),
	cell.Config(MTLSConfig{}),
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
	IPCache               *ipcache.IPCache
	AuthHandlers          []authHandler `group:"authHandlers"`
	DatapathAuthenticator datapathAuthenticator
}

type Manager interface {
	consumer.MonitorConsumer
}

func newManager(params authManagerParams) (Manager, error) {
	mgr, err := newAuthManager(params.AuthHandlers, params.DatapathAuthenticator, params.IPCache)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	dropMonitor := monitor.New(mgr, params.Config.MeshAuthMonitorQueueSize)

	params.Lifecycle.Append(hive.Hook{
		OnStart: dropMonitor.OnStart,
		OnStop:  dropMonitor.OnStop,
	})

	return dropMonitor, nil
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
