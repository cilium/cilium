// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipampkg "github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
)

// Restorer exposes the API to restore and regenerate the endpoints from a
// previous run and to wait until the regeneration is complete.
type Restorer struct {
	logger logrus.FieldLogger

	enabled bool
	dryMode bool

	stateDir                        string
	highScaleIPCache                bool
	ipv4                            bool
	ipv6                            bool
	bypassIPAvailabilityUponRestore bool

	clientset                k8sClient.Clientset
	endpointManager          endpointmanager.EndpointManager
	endpointMetadataResolver endpoint.MetadataResolverCB
	l7Proxy                  *proxy.Proxy
	localPods                k8s.LocalPodResource
	regenerator              *endpoint.Regenerator

	restoreComplete chan struct{}
}

// RestoreState holds the status of the in-progress restoration.
type RestoreState struct {
	Possible map[uint16]*endpoint.Endpoint
	Restored []*endpoint.Endpoint
	ToClean  []*endpoint.Endpoint
}

// FetchOldEndpoints reads the list of existing endpoints previously managed by Cilium when it was
// last run and associated it with container workloads. This function performs the first step in
// restoring the endpoint structure.  It needs to be followed by a call to RestoreOldEndpoints()
// once k8s has been initialized and RegenerateRestoredEndpoints() once the endpoint builder is
// ready. In summary:
//
// 1. FetchOldEndpoints(): Unmarshal old endpoints
//   - used to start DNS proxy with restored DNS history and rules
//
// 2. RestoreOldEndpoints(): validate endpoint data after k8s has been configured
//   - IP allocation
//   - some endpoints may be rejected and not regnerated in the 3rd step
//
// 3. RegenerateRestoredEndpoints(): Regenerate the restored endpoints
//   - recreate endpoint's policy, as well as bpf programs and maps
func (r *Restorer) FetchOldEndpoints(
	ctx context.Context,
	policyOwner regeneration.Owner,
	policyGetter endpoint.PolicyRepoGetter,
	namedPortsGetter endpoint.NamedPortsGetter,
	dir string,
) (*RestoreState, error) {
	if !r.enabled {
		r.logger.Info("Endpoint Restorer is disabled, skipping fetch step")
		return nil, nil
	}

	r.logger.WithField(logfields.Path, r.stateDir).Info("Reading old endpoints...")

	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possible := endpoint.ReadEPsFromDirNames(ctx, policyOwner, policyGetter, namedPortsGetter, dir, eptsID)
	if len(possible) == 0 {
		r.logger.WithField(logfields.Path, r.stateDir).Info("No old endpoints found.")
	}
	return &RestoreState{possible, nil, nil}, nil
}

// RestoreOldEndpoints performs the second step in restoring the endpoint structure,
// allocating their existing IPs out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// RegenerateRestoredEndpoints() once the endpoint builder is ready.
//
// If clean is true, endpoints which cannot be associated with a container
// workloads are deleted.
func (r *Restorer) RestoreOldEndpoints(
	ctx context.Context,
	state *RestoreState,
	emf endpoint.EndpointMetadataFetcher,
	allocator cache.IdentityAllocator,
	ipam *ipampkg.IPAM,
	clean bool,
) error {
	failed := 0

	if !r.enabled {
		r.logger.Info("Endpoint Restorer is disabled, skipping Restorer step")
		return nil
	}

	r.logger.Info("Restoring endpoints...")

	var (
		existingEndpoints map[string]lxcmap.EndpointInfo
		err               error
	)

	if !r.dryMode {
		existingEndpoints, err = lxcmap.DumpToMap()
		if err != nil {
			r.logger.WithError(err).Warning("Unable to open endpoint map while restoring. Skipping cleanup of endpoint map on startup")
		}
	}

	// endpoint metadata resolver is needed to validate an endpoint
	r.endpointMetadataResolver = endpoint.NewMetadataResolverCB(emf)

	for _, ep := range state.Possible {
		scopedLog := r.logger.WithField(logfields.EndpointID, ep.ID)
		if r.clientset.IsEnabled() {
			scopedLog = scopedLog.WithField(logfields.CEPName, ep.GetK8sNamespaceAndCEPName())
		}

		// We have to set the allocator for identities here during the Endpoint
		// lifecycle, because the identity allocator has been initialized *after*
		// endpoints are restored from disk. This is because we have to reserve
		// IPs for the endpoints that are restored via IPAM. Reserving of IPs
		// affects the allocation of IPs w.r.t. node addressing, which we need
		// to know before the identity allocator is initialized. We need to
		// know the node addressing because when adding a reference to the
		// kvstore because the local node's IP is used as a suffix for the key
		// in the key-value store.
		ep.SetAllocator(allocator)

		Restorer, err := r.validateEndpoint(ctx, ep, ipam)
		if err != nil {
			// Disconnected EPs are not failures, clean them silently below
			if !ep.IsDisconnecting() {
				r.endpointManager.DeleteK8sCiliumEndpointSync(ep)
				scopedLog.WithError(err).Warningf("Unable to Restorer endpoint, ignoring")
				failed++
			}
		}
		if !Restorer {
			if clean {
				state.ToClean = append(state.ToClean, ep)
			}
			continue
		}

		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOK(endpoint.Other, "Restoring endpoint from previous cilium instance")

		ep.SetDefaultConfiguration(true)
		ep.SetProxy(r.l7Proxy)
		ep.SkipStateClean()

		state.Restored = append(state.Restored, ep)

		if existingEndpoints != nil {
			delete(existingEndpoints, ep.GetIPv4Address())
			delete(existingEndpoints, ep.GetIPv6Address())
		}
	}

	r.logger.WithFields(logrus.Fields{
		"restored": len(state.Restored),
		"failed":   failed,
	}).Info("Endpoints restored")

	for epIP, info := range existingEndpoints {
		if ip := net.ParseIP(epIP); !info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				r.logger.WithError(err).Warn("Unable to delete obsolete endpoint from BPF map")
			} else {
				r.logger.Debugf("Removed outdated endpoint %d from endpoint map", info.LxcID)
			}
		}
	}

	state.Possible = nil

	return nil
}

func (r *Restorer) RegenerateRestoredEndpoints(state *RestoreState) {
	if !r.enabled {
		r.logger.Info("State restore is disabled. Existing endpoints on node are ignored")
		return
	}

	r.logger.WithField("numRestored", len(state.Restored)).Info("Regenerating restored endpoints")

	// Before regenerating, check whether the CT map has properties that
	// match this Cilium userspace instance. If not, it must be removed
	ctmap.DeleteIfUpgradeNeeded(nil)

	// we need to signalize when the endpoints are regenerated, i.e., when
	// they have finished to rebuild after being restored.
	epRegenerated := make(chan bool, len(state.Restored))

	// Insert all endpoints into the endpoint list first before starting
	// the regeneration. This is required to ensure that if an individual
	// regeneration causes an identity change of an endpoint, the new
	// identity will trigger a policy recalculation of all endpoints to
	// account for the new identity during the grace period. For this
	// purpose, all endpoints being restored must already be in the
	// endpoint list.
	for i := len(state.Restored) - 1; i >= 0; i-- {
		ep := state.Restored[i]
		// If the endpoint has local conntrack option enabled, then
		// check whether the CT map needs upgrading (and do so).
		if ep.Options.IsEnabled(option.ConntrackLocal) {
			ctmap.DeleteIfUpgradeNeeded(ep)
		}

		// Insert into endpoint manager so it can be regenerated when calls to
		// RegenerateAllEndpoints() are made. This must be done synchronously (i.e.,
		// not in a goroutine) because regenerateRestoredEndpoints must guarantee
		// upon returning that endpoints are exposed to other subsystems via
		// endpointmanager.
		if err := r.endpointManager.RestoreEndpoint(ep); err != nil {
			r.logger.WithError(err).Warning("Unable to Restorer endpoint")
			// remove endpoint from slice of endpoints to Restorer
			state.Restored = append(state.Restored[:i], state.Restored[i+1:]...)
		}
	}

	if option.Config.EnableIPSec {
		// If IPsec is enabled on EKS or AKS, we need to Restorer the host
		// endpoint before any other endpoint, to ensure a dropless upgrade.
		// This code can be removed in v1.15.
		// This is necessary because we changed how the IPsec encapsulation is
		// done. In older version, bpf_lxc would pass the outer destination IP
		// via skb->cb to bpf_host which would write it to the outer header.
		// In newer versions, the header is written by the kernel XFRM
		// subsystem and bpf_host must therefore not write it. To allow for a
		// smooth upgrade, bpf_host has been updated to handle both cases. But
		// for that to succeed, it must be reloaded first, before the bpf_lxc
		// programs stop writing the IP into skb->cb.
		for _, ep := range state.Restored {
			// Cap the timeout used to wait for remote cluster synchronization
			// to avoid blocking the agent startup, as this regeneration is
			// performed synchronously.
			r.regenerator.CapTimeoutForSynchronousRegeneration()

			if ep.IsHost() {
				r.logger.WithField(logfields.EndpointID, ep.ID).Info("Successfully restored endpoint. Scheduling regeneration")
				if err := ep.RegenerateAfterRestore(r.regenerator); err != nil {
					r.logger.WithField(logfields.EndpointID, ep.ID).WithError(err).Debug("error regenerating restored host endpoint")
					epRegenerated <- false
				} else {
					epRegenerated <- true
				}
				break
			}
		}
	}

	for _, ep := range state.Restored {
		if ep.IsHost() && option.Config.EnableIPSec {
			// The host endpoint was handled above.
			continue
		}
		r.logger.WithField(logfields.EndpointID, ep.ID).Info("Successfully restored endpoint. Scheduling regeneration")
		go func(ep *endpoint.Endpoint, epRegenerated chan<- bool) {
			if err := ep.RegenerateAfterRestore(r.regenerator); err != nil {
				r.logger.WithField(logfields.EndpointID, ep.ID).WithError(err).Debug("error regenerating during restore")
				epRegenerated <- false
				return
			}
			epRegenerated <- true
		}(ep, epRegenerated)
	}

	var endpointCleanupCompleted sync.WaitGroup
	for _, ep := range state.ToClean {
		endpointCleanupCompleted.Add(1)
		go func(ep *endpoint.Endpoint) {
			// The IP was not allocated yet so does not need to be freed.
			// The identity may be allocated in the kvstore but we can't
			// release it easily as it will require to block on kvstore
			// connectivity which we can't do at this point. Let the lease
			// expire to release the identity.
			r.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{
				NoIdentityRelease: true,
				NoIPRelease:       true,
			})
			endpointCleanupCompleted.Done()
		}(ep)
	}
	endpointCleanupCompleted.Wait()

	go func() {
		regenerated, total := 0, 0
		if len(state.Restored) > 0 {
			for buildSuccess := range epRegenerated {
				if buildSuccess {
					regenerated++
				}
				total++
				if total >= len(state.Restored) {
					break
				}
			}
		}
		close(epRegenerated)

		r.logger.WithFields(logrus.Fields{
			"regenerated": regenerated,
			"total":       total,
		}).Info("Finished regenerating restored endpoints")
		close(r.restoreComplete)
	}()
}

func (r *Restorer) WaitForRestore(ctx context.Context) {
	if !r.enabled {
		return
	}

	select {
	case <-ctx.Done():
	case <-r.restoreComplete:
	}
}

type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Clientset k8sClient.Clientset

	EndpointManager endpointmanager.EndpointManager
	L7Proxy         *proxy.Proxy
	LocalPods       k8s.LocalPodResource
	Regenerator     *endpoint.Regenerator
}

func newRestorer(cfg *option.DaemonConfig, p params) *Restorer {
	return &Restorer{
		logger:                          p.Logger,
		enabled:                         cfg.RestoreState,
		stateDir:                        cfg.StateDir,
		dryMode:                         cfg.DryMode,
		highScaleIPCache:                cfg.EnableHighScaleIPcache,
		ipv4:                            cfg.EnableIPv4,
		ipv6:                            cfg.EnableIPv6,
		bypassIPAvailabilityUponRestore: cfg.BypassIPAvailabilityUponRestore,
		clientset:                       p.Clientset,
		endpointManager:                 p.EndpointManager,
		l7Proxy:                         p.L7Proxy,
		localPods:                       p.LocalPods,
		regenerator:                     p.Regenerator,
		restoreComplete:                 make(chan struct{}),
	}
}

// validateEndpoint attempts to determine that the restored endpoint is valid, ie it
// still exists in k8s, its datapath devices are present, and Cilium is
// responsible for its workload, etc.
//
// Returns true to indicate that the endpoint is valid to Restorer, and an
// optional error.
func (r *Restorer) validateEndpoint(ctx context.Context, ep *endpoint.Endpoint, ipam *ipampkg.IPAM) (valid bool, err error) {
	// On each restart, the health endpoint is supposed to be recreated.
	// Hence we need to clean health endpoint state unconditionally.
	if ep.HasLabels(labels.LabelHealth) {
		// Ignore health endpoint and don't report
		// it as not restored. But we need to clean up the old
		// state files, so do this now.
		healthStateDir := ep.StateDirectoryPath()
		scopedLog := r.logger.WithFields(logrus.Fields{
			logfields.EndpointID: ep.ID,
			logfields.Path:       healthStateDir,
		})
		scopedLog.Debug("Removing old health endpoint state directory")
		if err := os.RemoveAll(healthStateDir); err != nil {
			scopedLog.Warning("Cannot clean up old health state directory")
		}
		return false, nil
	}

	if ep.K8sPodName != "" && ep.K8sNamespace != "" && r.clientset.IsEnabled() {
		if err := r.getPodForEndpoint(ctx, ep); err != nil {
			return false, err
		}

		// Initialize the endpoint's event queue because the following call to
		// execute the metadata resolver will emit events for the endpoint.
		// After this endpoint is validated, it'll eventually be restored, in
		// which the endpoint manager will begin processing the events off the
		// queue.
		ep.InitEventQueue()

		ep.RunMetadataResolver(r.endpointMetadataResolver)
	}

	if err := ep.ValidateConnectorPlumbing(checkLink); err != nil {
		return false, err
	}

	if !ep.DatapathConfiguration.ExternalIpam {
		if err := r.allocateIPs(ep, ipam); err != nil {
			return false, fmt.Errorf("failed to re-allocate IP of endpoint: %s", err)
		}
	}

	return true, nil
}

func (r *Restorer) getPodForEndpoint(ctx context.Context, ep *endpoint.Endpoint) error {
	if option.Config.EnableHighScaleIPcache {
		_, _, _, _, _, err := r.endpointMetadataResolver(ep.K8sNamespace, ep.K8sPodName)
		return err
	}

	store, err := r.localPods.Store(ctx)
	if err != nil {
		return err
	}

	podName := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      ep.K8sPodName,
			Namespace: ep.K8sNamespace,
		},
	}
	_, _, err = store.Get(podName)
	if err != nil && k8serrors.IsNotFound(err) {
		return fmt.Errorf("kubernetes pod %s/%s does not exist", ep.K8sNamespace, ep.K8sPodName)
	}

	return nil
}

// checkLink returns an error if a link with linkName does not exist.
func checkLink(linkName string) error {
	_, err := netlink.LinkByName(linkName)
	return err
}

func (r *Restorer) allocateIPs(ep *endpoint.Endpoint, ipam *ipampkg.IPAM) (err error) {
	if r.ipv6 && ep.IPv6.IsValid() {
		ipv6Pool := ipampkg.PoolOrDefault(ep.IPv6IPAMPool)
		_, err = ipam.AllocateIPWithoutSyncUpstream(ep.IPv6.AsSlice(), ep.HumanString()+" [restored]", ipv6Pool)
		if err != nil {
			return fmt.Errorf("unable to reallocate %s IPv6 address: %w", ep.IPv6, err)
		}

		defer func() {
			if err != nil {
				ipam.ReleaseIP(ep.IPv6.AsSlice(), ipv6Pool)
			}
		}()
	}

	if r.ipv4 && ep.IPv4.IsValid() {
		ipv4Pool := ipampkg.PoolOrDefault(ep.IPv4IPAMPool)
		_, err = ipam.AllocateIPWithoutSyncUpstream(ep.IPv4.AsSlice(), ep.HumanString()+" [restored]", ipv4Pool)
		switch {
		// We only check for BypassIPAllocUponRestore for IPv4 because we
		// assume that this flag is only turned on for IPv4-only IPAM modes
		// such as ENI.
		//
		// Additionally, only check for a specific error which can be caused by
		// https://github.com/cilium/cilium/pull/15453. Other errors are not
		// bypassed.
		case err != nil &&
			errors.Is(err, ipampkg.NewIPNotAvailableInPoolError(ep.IPv4.AsSlice())) &&
			r.bypassIPAvailabilityUponRestore:
			r.logger.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr:     ep.IPv4,
				logfields.EndpointID: ep.ID,
				logfields.CEPName:    ep.GetK8sNamespaceAndCEPName(),
			}).Warn(
				"Bypassing IP not available error on endpoint Restorer. This is " +
					"to prevent errors upon Cilium upgrade and should not be " +
					"relied upon. Consider restarting this pod in order to get " +
					"a fresh IP from the pool.",
			)
		case err != nil:
			return fmt.Errorf("unable to reallocate %s IPv4 address: %w", ep.IPv4, err)
		}
	}

	return nil
}
