// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"cmp"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

// Cell provides the IdentityAllocator for allocating security identities
var Cell = cell.Module(
	"identity",
	"Allocating and managing security identities",

	cell.Provide(newIdentityAllocator),
	cell.Config(defaultConfig),
)

// CachingIdentityAllocator provides an abstraction over the concrete type in
// pkg/identity/cache so that the underlying implementation can be mocked out
// in unit tests.
type CachingIdentityAllocator interface {
	cache.IdentityAllocator
	clustermesh.RemoteIdentityWatcher

	InitIdentityAllocator(versioned.Interface) <-chan struct{}

	// RestoreLocalIdentities reads in the checkpointed local allocator state
	// from disk and allocates a reference to every previously existing identity.
	//
	// Once all identity-allocating objects are synchronized (e.g. network policies,
	// remote nodes), call ReleaseRestoredIdentities to release the held references.
	RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error)

	// ReleaseRestoredIdentities releases any identities that were restored, reducing their reference
	// count and cleaning up as necessary.
	ReleaseRestoredIdentities()

	Close()

	LocalIdentityChanges() stream.Observable[cache.IdentityChange]
}

type identityAllocatorParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	IDUpdater policycell.IdentityUpdater

	IdentityHandlers []identity.UpdateIdentities `group:"identity-handlers"`

	Config config
}

type identityAllocatorOut struct {
	cell.Out

	IdentityAllocator      CachingIdentityAllocator
	CacheIdentityAllocator cache.IdentityAllocator
	RemoteIdentityWatcher  clustermesh.RemoteIdentityWatcher
	IdentityObservable     stream.Observable[cache.IdentityChange]
}

type config struct {
	IdentityManagementMode string `mapstructure:"identity-management-mode"`
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.String(option.IdentityManagementMode, c.IdentityManagementMode, "Configure whether Cilium Identities are managed by cilium-agent, cilium-operator, or both")
}

var defaultConfig = config{
	IdentityManagementMode: option.IdentityManagementModeAgent,
}

func newIdentityAllocator(params identityAllocatorParams) identityAllocatorOut {
	// iao: updates SelectorCache and regenerates endpoints when
	// identity allocation / deallocation has occurred.
	iao := &identityAllocatorOwner{
		IdentityUpdater: params.IDUpdater,
		logger:          params.Log,
	}

	var idAlloc CachingIdentityAllocator

	if option.NetworkPolicyEnabled(option.Config) {
		isOperatorManageCIDsEnabled := cmp.Or(
			params.Config.IdentityManagementMode == option.IdentityManagementModeOperator,
			params.Config.IdentityManagementMode == option.IdentityManagementModeBoth,
		)

		allocatorConfig := cache.AllocatorConfig{
			EnableOperatorManageCIDs: isOperatorManageCIDsEnabled,
		}

		// Allocator: allocates local and cluster-wide security identities.
		cacheIDAlloc := cache.NewCachingIdentityAllocator(params.Log, iao, allocatorConfig)
		cacheIDAlloc.EnableCheckpointing()

		idAlloc = cacheIDAlloc
	} else {
		idAlloc = cache.NewNoopIdentityAllocator(params.Log)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			idAlloc.Close()
			return nil
		},
	})

	return identityAllocatorOut{
		IdentityAllocator:      idAlloc,
		CacheIdentityAllocator: idAlloc,
		RemoteIdentityWatcher:  idAlloc,
		IdentityObservable:     idAlloc,
	}
}

type identityAllocatorOwner struct {
	policycell.IdentityUpdater
	logger *slog.Logger
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (iao *identityAllocatorOwner) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4(logging.DefaultSlogLogger)
	case option.Config.EnableIPv6:
		ip = node.GetIPv6(logging.DefaultSlogLogger)
	}

	if ip == nil {
		logging.Fatal(iao.logger, "Node IP not available yet")
	}

	return ip.String()
}
