// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	policyRestAPI "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"namemanager",
	"maintains DNS mappings to implement toFQDN policy",

	// Cannot just yet be a proper cell.Config, since there's places which
	// access the MinTTL without access to a hive. In addition, the state dir is
	// a shared config.
	cell.Config(defaultConfig),
	cell.ProvidePrivate(func(dc *option.DaemonConfig, lc NameManagerLocalConfig) NameManagerConfig {
		return NameManagerConfig{
			NameManagerLocalConfig: lc,
			MinTTL:                 dc.ToFQDNsMinTTL,
			DNSProxyLockCount:      dc.DNSProxyLockCount,
			StateDir:               dc.StateDir,
			EnableIPv4:             dc.EnableIPv4,
			EnableIPv6:             dc.EnableIPv6,
		}
	}),
	cell.ProvidePrivate(adaptors),
	cell.Provide(newForCell),
	cell.Provide(registerEndpointRestorationNotifier),

	cell.ProvidePrivate(New), // for the API handlers, exposes *manager.
	cell.Provide(handlers),
)

type NameManagerConfig struct {
	NameManagerLocalConfig

	// MinTTL is the minimum TTL value that a cache entry can have.
	MinTTL int

	// DNSProxyLockCount is used to shard serialization of updates to DNS names.
	DNSProxyLockCount int

	// StateDir is the directory where namemanager checkpoints are stored.
	StateDir string

	EnableIPv4, EnableIPv6 bool
}

type NameManagerLocalConfig struct {
	ToFQDNsPreAllocate bool `mapstructure:"tofqdns-preallocate-identities"`
}

type ManagerParams struct {
	cell.In

	JobGroup job.Group

	PolicyRepo      policy.PolicyRepository
	Logger          *slog.Logger
	Config          NameManagerConfig
	IPCache         ipc
	EPMgr           endpoints
	RestorerPromise promise.Promise[endpointstate.Restorer]
	Allocator       cache.IdentityAllocator
}

func adaptors(ipcache *ipcache.IPCache, epLookup endpointmanager.EndpointsLookup) (ipc, endpoints) {
	return ipcache, epLookup
}

// The parts of the ipcache the namemanager needs - abstracted so that injecting
// a mock is easier in testing.
type ipc interface {
	UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64)
	RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64)
	WaitForRevision(ctx context.Context, rev uint64) error
}

type endpoints interface {
	Lookup(id string) (*endpoint.Endpoint, error)
	GetEndpoints() []*endpoint.Endpoint
}

var defaultConfig = NameManagerLocalConfig{
	ToFQDNsPreAllocate: true,
}

func (def NameManagerLocalConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("tofqdns-preallocate-identities", def.ToFQDNsPreAllocate, "Preallocate identities for ToFQDN selectors. This reduces proxied DNS response latency. Disable if you have many ToFQDN selectors.")
}

// Only exists such that we have constructor which returns the interface type.
func newForCell(m *manager) NameManager {
	return m
}

func registerEndpointRestorationNotifier(m *manager) endpointstate.RestorationNotifierOut {
	return endpointstate.RestorationNotifierOut{
		Restorer: m,
	}
}

// The NameManager maintains DNS mappings which need to be tracked, due to
// FQDNSelectors. It is the main structure which relates the FQDN subsystem to
// the policy subsystem for plumbing the relation between a DNS name and the
// corresponding IPs which have been returned via DNS lookups. Name to IP
// mappings are inserted into the ipcache.
type NameManager interface {
	// RegisterFQDNSelector exposes this FQDNSelector so that the identity labels
	// of IPs contained in a DNS response that matches said selector can be
	// associated with that selector.
	// This function also evaluates if any DNS names in the cache are matched by
	// this new selector and updates the labels for those DNS names accordingly.
	RegisterFQDNSelector(selector api.FQDNSelector) (ipcacheRevision uint64)

	// UnregisterFQDNSelector removes this FQDNSelector from the set of
	// IPs which are being tracked by the identityNotifier. The result
	// of this is that an IP may be evicted from IPCache if it is no longer
	// selected by any other FQDN selector.
	UnregisterFQDNSelector(selector api.FQDNSelector) (ipcacheRevision uint64)
	// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
	// have changed for a name they will be reflected in updatedDNSIPs.
	UpdateGenerateDNS(ctx context.Context, lookupTime time.Time, name string, record *fqdn.DNSIPRecords, caches ...*fqdn.DNSCache) <-chan error

	// LockName is used to serialize  parallel end-to-end updates to the same name.
	LockName(name string)
	// UnlockName releases a lock previously acquired by LockName()
	UnlockName(name string)
}

// Provides the API handlers for Cilium API.
type apiHandlers struct {
	cell.Out

	PolicyDeleteFqdnCacheHandler policyRestAPI.DeleteFqdnCacheHandler
	PolicyGetFqdnCacheHandler    policyRestAPI.GetFqdnCacheHandler
	PolicyGetFqdnCacheIDHandler  policyRestAPI.GetFqdnCacheIDHandler
	PolicyGetFqdnNamesHandler    policyRestAPI.GetFqdnNamesHandler
}

func handlers(nm *manager) apiHandlers {
	return apiHandlers{
		PolicyDeleteFqdnCacheHandler: &deleteFQDNCacheHandler{nm},
		PolicyGetFqdnCacheHandler:    &getFQDNCacheHandler{nm},
		PolicyGetFqdnCacheIDHandler:  &getFQDNCacheIDHandler{nm},
		PolicyGetFqdnNamesHandler:    &getFQDNNamesHandler{nm},
	}
}
