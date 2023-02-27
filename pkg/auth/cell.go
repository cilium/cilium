// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"github.com/cilium/cilium/pkg/auth/monitor"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
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

	cell.Provide(newManager),
)

type authManagerParams struct {
	cell.In

	EndpointManager endpointmanager.EndpointManager
}

type Manager interface {
	consumer.MonitorConsumer
}

func newManager(params authManagerParams) Manager {
	return monitor.AddAuthManager(NewAuthManager(params.EndpointManager))
}
