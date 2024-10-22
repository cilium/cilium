// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/auth/spire"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/maps/authmap"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides AuthManager which is responsible for request authentication.
// It does this by registering to "auth required" signals from the signal package
// and reacting upon received signal events.
// Actual authentication gets performed by an auth handler which is
// responsible for the configured auth type on the corresponding policy.
var Cell = cell.Module(
	"auth",
	"Authenticates requests as demanded by policy",

	spire.Cell,

	// The auth manager is the main entry point which gets registered to signal map and receives auth requests.
	// In addition, it handles re-authentication and auth map garbage collection.
	cell.Provide(registerAuthManager),
	cell.ProvidePrivate(
		// Null auth handler provides support for auth type "null" - which always succeeds.
		newMutualAuthHandler,
		// Always fail auth handler provides support for auth type "always-fail" - which always fails.
		newAlwaysFailAuthHandler,
	),
	cell.Config(config{
		MeshAuthEnabled:               true,
		MeshAuthQueueSize:             1024,
		MeshAuthGCInterval:            5 * time.Minute,
		MeshAuthSignalBackoffDuration: 1 * time.Second, // this default is based on the default TCP retransmission timeout
	}),
	cell.Config(MutualAuthConfig{}),
)

type config struct {
	MeshAuthEnabled               bool
	MeshAuthQueueSize             int
	MeshAuthGCInterval            time.Duration
	MeshAuthSignalBackoffDuration time.Duration
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Bool("mesh-auth-enabled", r.MeshAuthEnabled, "Enable authentication processing & garbage collection (beta)")
	flags.Int("mesh-auth-queue-size", r.MeshAuthQueueSize, "Queue size for the auth manager")
	flags.Duration("mesh-auth-gc-interval", r.MeshAuthGCInterval, "Interval in which auth entries are attempted to be garbage collected")
	flags.Duration("mesh-auth-signal-backoff-duration", r.MeshAuthSignalBackoffDuration, "Time to wait betweeen two authentication required signals in case of a cache mismatch")
	flags.MarkHidden("mesh-auth-signal-backoff-duration")
}

type authManagerParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Health    cell.Health

	Config       config
	AuthMap      authmap.Map
	AuthHandlers []authHandler `group:"authHandlers"`

	SignalManager   signal.SignalManager
	NodeIDHandler   types.NodeIDHandler
	IdentityChanges stream.Observable[cache.IdentityChange]
	NodeManager     nodeManager.NodeManager
	EndpointManager endpointmanager.EndpointManager
	PolicyRepo      *policy.Repository
}

func registerAuthManager(params authManagerParams) (*AuthManager, error) {
	if !params.Config.MeshAuthEnabled {
		params.Logger.Info("Authentication processing is disabled")
		return nil, nil
	}

	// Instantiate & wire auth components

	mapWriter := newAuthMapWriter(params.Logger, params.AuthMap)
	mapCache := newAuthMapCache(params.Logger, mapWriter)

	mgr, err := newAuthManager(params.Logger, params.AuthHandlers, mapCache, params.NodeIDHandler, params.Config.MeshAuthSignalBackoffDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	mapGC := newAuthMapGC(params.Logger, mapCache, params.NodeIDHandler, params.PolicyRepo)

	// Register auth components to lifecycle hooks & jobs

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			if err := mapCache.restoreCache(); err != nil {
				return fmt.Errorf("failed to restore auth map cache: %w", err)
			}

			return nil
		},
	})

	if err := registerSignalAuthenticationJob(params.JobGroup, mgr, params.SignalManager, params.Config); err != nil {
		return nil, fmt.Errorf("failed to register signal authentication job: %w", err)
	}
	registerReAuthenticationJob(params.JobGroup, mgr, params.AuthHandlers)
	registerGCJobs(params.JobGroup, params.Lifecycle, mapGC, params.Config, params.NodeManager, params.EndpointManager, params.IdentityChanges)

	return mgr, nil
}

func registerReAuthenticationJob(jobGroup job.Group, mgr *AuthManager, authHandlers []authHandler) {
	for _, ah := range authHandlers {
		if ah != nil && ah.subscribeToRotatedIdentities() != nil {
			jobGroup.Add(job.Observer("auth-re-authentication", mgr.handleCertificateRotationEvent, stream.FromChannel(ah.subscribeToRotatedIdentities())))
		}
	}
}

func registerSignalAuthenticationJob(jobGroup job.Group, mgr *AuthManager, sm signal.SignalManager, config config) error {
	var signalChannel = make(chan signalAuthKey, config.MeshAuthQueueSize)

	// RegisterHandler registers signalChannel with SignalManager, but flow of events
	// starts later during the OnStart hook of the SignalManager
	if err := sm.RegisterHandler(signal.ChannelHandler(signalChannel), signal.SignalAuthRequired); err != nil {
		return fmt.Errorf("failed to set up signal channel for datapath authentication required events: %w", err)
	}

	jobGroup.Add(job.Observer("auth-request-authentication", mgr.handleAuthRequest, stream.FromChannel(signalChannel)))

	return nil
}

func registerGCJobs(jobGroup job.Group, lifecycle cell.Lifecycle, mapGC *authMapGarbageCollector, cfg config, nodeManager nodeManager.NodeManager, endpointManager endpointmanager.EndpointManager, identityChanges stream.Observable[cache.IdentityChange]) {
	lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			mapGC.subscribeToNodeEvents(nodeManager)
			mapGC.subscribeToEndpointEvents(endpointManager)
			return nil
		},
		OnStop: func(hookContext cell.HookContext) error {
			nodeManager.Unsubscribe(mapGC)
			endpointManager.Unsubscribe(mapGC)
			return nil
		},
	})

	jobGroup.Add(job.Observer("auth-gc-identity-events", mapGC.handleIdentityChange, identityChanges))
	jobGroup.Add(job.Timer("auth-gc-cleanup", mapGC.cleanup, cfg.MeshAuthGCInterval))
}

type authHandlerResult struct {
	cell.Out

	AuthHandler authHandler `group:"authHandlers"`
}
