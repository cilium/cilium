// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"

	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type nphdsResourceStore interface {
	updateNetworkPolicyHosts(context.Context, string, func(*envoyAPI.NetworkPolicyHosts) (*envoyAPI.NetworkPolicyHosts, error)) error
}

// nphdsCacheAdapter bridges the IPCache and the ADS cache's NPHDS resources.
// It implements ipcache.IPIdentityMappingListener.
type nphdsCacheAdapter struct {
	logger *slog.Logger
	store  nphdsResourceStore
	mutex  lock.Mutex
}

var _ ipcache.IPIdentityMappingListener = (*nphdsCacheAdapter)(nil)

func newNPHDSCacheAdapter(logger *slog.Logger, store nphdsResourceStore) *nphdsCacheAdapter {
	return &nphdsCacheAdapter{
		logger: logger,
		store:  store,
	}
}

// OnIPIdentityCacheChange pushes modifications to the IP<->Identity mapping
// into ADS NPHDS resources, mirroring the old NPHDSCache behaviour.
func (a *nphdsCacheAdapter) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8,
) {
	cidr := cidrCluster.AsIPNet()
	cidrStr := cidr.String()
	resourceName := newID.ID.StringID()

	scopedLog := a.logger.With(
		logfields.IPAddr, cidrStr,
		logfields.Identity, resourceName,
		logfields.Modification, modType,
	)

	switch modType {
	case ipcache.Upsert:
		// Delete the CIDR from the old identity first, if it changed.
		if oldID != nil && oldID.ID != newID.ID {
			a.OnIPIdentityCacheChange(ipcache.Delete, cidrCluster, nil, nil, nil, *oldID, encryptKey, k8sMeta, endpointFlags)
		}
		if err := a.handleIPUpsert(resourceName, cidrStr, newID.ID); err != nil {
			scopedLog.Warn("NPHDS upsert failed", logfields.Error, err)
		}
	case ipcache.Delete:
		if err := a.handleIPDelete(resourceName, cidrStr); err != nil {
			scopedLog.Warn("NPHDS delete failed", logfields.Error, err)
		}
	}
}

func (a *nphdsCacheAdapter) updateResource(identityStr string, mutate func(*envoyAPI.NetworkPolicyHosts) (*envoyAPI.NetworkPolicyHosts, error)) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return a.store.updateNetworkPolicyHosts(context.Background(), identityStr, mutate)
}

func (a *nphdsCacheAdapter) handleIPUpsert(identityStr, cidrStr string, newID identity.NumericIdentity) error {
	return a.updateResource(identityStr, func(npHost *envoyAPI.NetworkPolicyHosts) (*envoyAPI.NetworkPolicyHosts, error) {
		var hostAddresses []string
		if npHost != nil {
			if slices.Contains(npHost.HostAddresses, cidrStr) {
				return npHost, nil
			}
			hostAddresses = make([]string, 0, len(npHost.HostAddresses)+1)
			hostAddresses = append(hostAddresses, npHost.HostAddresses...)
			hostAddresses = append(hostAddresses, cidrStr)
			slices.Sort(hostAddresses)
		} else {
			hostAddresses = []string{cidrStr}
		}

		newNpHost := &envoyAPI.NetworkPolicyHosts{
			Policy:        uint64(newID),
			HostAddresses: hostAddresses,
		}
		if err := newNpHost.Validate(); err != nil {
			return nil, fmt.Errorf("could not validate NPHDS resource update on upsert: %s (%w)", newNpHost.String(), err)
		}
		return newNpHost, nil
	})
}

func (a *nphdsCacheAdapter) handleIPDelete(identityStr, cidrStr string) error {
	return a.updateResource(identityStr, func(npHost *envoyAPI.NetworkPolicyHosts) (*envoyAPI.NetworkPolicyHosts, error) {
		if npHost == nil {
			return nil, nil
		}

		targetIndex := slices.Index(npHost.HostAddresses, cidrStr)
		if targetIndex < 0 {
			return nil, fmt.Errorf("can't find IP %s in NPHDS cache for identity %s", cidrStr, identityStr)
		}

		if len(npHost.HostAddresses) <= 1 {
			return nil, nil
		}

		hostAddresses := make([]string, 0, len(npHost.HostAddresses)-1)
		hostAddresses = append(hostAddresses, npHost.HostAddresses[:targetIndex]...)
		hostAddresses = append(hostAddresses, npHost.HostAddresses[targetIndex+1:]...)

		newNpHost := &envoyAPI.NetworkPolicyHosts{
			Policy:        npHost.Policy,
			HostAddresses: hostAddresses,
		}
		if err := newNpHost.Validate(); err != nil {
			return nil, fmt.Errorf("could not validate NPHDS resource update on delete: %s (%w)", newNpHost.String(), err)
		}
		return newNpHost, nil
	})
}

func (s *adsServer) updateNetworkPolicyHosts(ctx context.Context, name string, mutate func(*envoyAPI.NetworkPolicyHosts) (*envoyAPI.NetworkPolicyHosts, error)) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	resource, _ := s.cache.GetResource(localNodeID, typeurl.NetworkPolicyHosts, name)
	current, _ := resource.(*envoyAPI.NetworkPolicyHosts)
	next, err := mutate(current)
	if err != nil {
		return err
	}
	if next == current {
		return nil
	}
	if next == nil {
		_, rollback, err := s.cache.RemoveNetworkPolicyHosts(ctx, localNodeID, name)
		finalizeRollback(rollback)
		return err
	}
	_, rollback, err := s.cache.UpsertNetworkPolicyHosts(ctx, localNodeID, name, next)
	finalizeRollback(rollback)
	return err
}

func newNPHDSIPCacheListenerCallbacks(logger *slog.Logger, ipCache IPCacheEventSource, store nphdsResourceStore) envoy_server.CallbackFuncs {
	var once sync.Once
	return envoy_server.CallbackFuncs{
		StreamRequestFunc: func(_ int64, req *discovery.DiscoveryRequest) error {
			if req.GetTypeUrl() == NetworkPolicyHostsTypeURL {
				once.Do(func() {
					startNPHDSIPCacheListener(logger, ipCache, store)
				})
			}
			return nil
		},
	}
}

// startNPHDSIPCacheListener starts listening to IPCache events and populating
// the ADS NPHDS resources.
func startNPHDSIPCacheListener(logger *slog.Logger, ipCache IPCacheEventSource, store nphdsResourceStore) {
	if ipCache == nil {
		return
	}
	adapter := newNPHDSCacheAdapter(logger, store)
	ipCache.AddListener(adapter)
}
