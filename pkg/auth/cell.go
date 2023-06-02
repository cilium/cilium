// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/auth/spire"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/signal"
)

// Cell invokes authManager which is responsible for request authentication.
// It does this by registering to "auth required" signals from the signal package
// and reacting upon received signal events.
// Actual authentication gets performed by an auth handler which is
// responsible for the configured auth type on the corresponding policy.
var Cell = cell.Module(
	"auth-manager",
	"Authenticates requests as demanded by policy",

	spire.Cell,

	// The manager is the main entry point which gets registered to signal map and receives auth requests.
	cell.Invoke(newManager),
	cell.ProvidePrivate(
		newSignalRegistration,
		// Null auth handler provides support for auth type "null" - which always succeeds.
		newNullAuthHandler,
		// MTLS auth handler provides support for auth type "mtls-*" - which performs mTLS authentication.
		newMTLSAuthHandler,
		// Always fail auth handler provides support for auth type "always-fail" - which always fails.
		newAlwaysFailAuthHandler,
	),
	cell.Config(config{MeshAuthQueueSize: 1024}),
	cell.Config(MTLSConfig{}),
)

type config struct {
	MeshAuthQueueSize int
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Int("mesh-auth-queue-size", r.MeshAuthQueueSize, "Queue size for the auth manager")
}

func newSignalRegistration(sm signal.SignalManager, config config) (<-chan signalAuthKey, error) {
	var signalChannel = make(chan signalAuthKey, config.MeshAuthQueueSize)

	// RegisterHandler registers signalChannel with SignalManager, but flow of events
	// starts later during the OnStart hook of the SignalManager
	err := sm.RegisterHandler(signal.ChannelHandler(signalChannel), signal.SignalAuthRequired)
	if err != nil {
		return nil, fmt.Errorf("failed to set up signal channel for datapath authentication required events: %w", err)
	}
	return signalChannel, nil
}

type authManagerParams struct {
	cell.In

	Lifecycle     hive.Lifecycle
	Config        config
	IPCache       *ipcache.IPCache
	AuthHandlers  []authHandler `group:"authHandlers"`
	AuthMap       authmap.Map
	SignalChannel <-chan signalAuthKey
}

func newManager(params authManagerParams) error {
	mapWriter := newAuthMapWriter(params.AuthMap)
	mapCache := newAuthMapCache(mapWriter)

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(hookContext hive.HookContext) error {
			if err := mapCache.restoreCache(); err != nil {
				return fmt.Errorf("failed to restore auth map cache: %w", err)
			}

			return nil
		},
	})

	mgr, err := newAuthManager(params.SignalChannel, params.AuthHandlers, mapCache, params.IPCache)
	if err != nil {
		return fmt.Errorf("failed to create auth manager: %w", err)
	}

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startCtx hive.HookContext) error {
			mgr.start()
			return nil
		},
	})

	return nil
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
