// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"

	"github.com/cilium/cilium/pkg/auth/monitor"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
)

var Cell = cell.Module(
	"auth-manager",
	"Authentication Manager",

	cell.Provide(newManager),
	cell.ProvidePrivate(newNullAuthHandler),
)

type authManagerParams struct {
	cell.In

	EndpointManager endpointmanager.EndpointManager
	AuthHandlers    []authHandler `group:"authHandlers"`
}

type Manager interface {
	consumer.MonitorConsumer
}

func newManager(params authManagerParams) (Manager, error) {
	manager, err := newAuthManager(params.EndpointManager, params.AuthHandlers)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	return monitor.New(manager), nil
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
