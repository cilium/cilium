// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

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

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type endpointRestoreState struct {
	possible map[uint16]*endpoint.Endpoint
	restored []*endpoint.Endpoint
	toClean  []*endpoint.Endpoint
}

// checkLink returns an error if a link with linkName does not exist.
func checkLink(linkName string) error {
	_, err := netlink.LinkByName(linkName)
	return err
}

// validateEndpoint attempts to determine that the restored endpoint is valid, ie it
// still exists in k8s, its datapath devices are present, and Cilium is
// responsible for its workload, etc.
//
// Returns true to indicate that the endpoint is valid to restore, and an
// optional error.
func (d *Daemon) validateEndpoint(ep *endpoint.Endpoint) (valid bool, err error) {
	// On each restart, the health endpoint is supposed to be recreated.
	// Hence we need to clean health endpoint state unconditionally.
	if ep.HasLabels(labels.LabelHealth) {
		// Ignore health endpoint and don't report
		// it as not restored. But we need to clean up the old
		// state files, so do this now.
		healthStateDir := ep.StateDirectoryPath()
		scopedLog := log.WithFields(logrus.Fields{
			logfields.EndpointID: ep.ID,
			logfields.Path:       healthStateDir,
		})
		scopedLog.Debug("Removing old health endpoint state directory")
		if err := os.RemoveAll(healthStateDir); err != nil {
			scopedLog.Warning("Cannot clean up old health state directory")
		}
		return false, nil
	}

	if ep.K8sPodName != "" && ep.K8sNamespace != "" && d.clientset.IsEnabled() {
		if err := d.getPodForEndpoint(ep); err != nil {
			return false, err
		}

		// Initialize the endpoint's event queue because the following call to
		// execute the metadata resolver will emit events for the endpoint.
		// After this endpoint is validated, it'll eventually be restored, in
		// which the endpoint manager will begin processing the events off the
		// queue.
		ep.InitEventQueue()
		ep.RunMetadataResolver(d.fetchK8sMetadataForEndpoint)
	}

	if err := ep.ValidateConnectorPlumbing(checkLink); err != nil {
		return false, err
	}

	if !ep.DatapathConfiguration.ExternalIpam {
		if err := d.allocateIPsLocked(ep); err != nil {
			return false, fmt.Errorf("Failed to re-allocate IP of endpoint: %s", err)
		}
	}

	return true, nil
}

func (d *Daemon) getPodForEndpoint(ep *endpoint.Endpoint) error {
	var (
		pod *slim_corev1.Pod
		err error
	)
	if option.Config.EnableHighScaleIPcache {
		pod, _, _, _, _, err = d.fetchK8sMetadataForEndpoint(ep.K8sNamespace, ep.K8sPodName)
	} else {
		d.k8sWatcher.WaitForCacheSync(resources.K8sAPIGroupPodV1Core)
		pod, err = d.k8sWatcher.GetCachedPod(ep.K8sNamespace, ep.K8sPodName)
	}
	if err != nil && k8serrors.IsNotFound(err) {
		return fmt.Errorf("Kubernetes pod %s/%s does not exist", ep.K8sNamespace, ep.K8sPodName)
	} else if err == nil && pod.Spec.NodeName != nodeTypes.GetName() {
		// if flag `option.Config.K8sEventHandover` is false and CiliumEndpointCRD is disabled,
		// `GetCachedPod` may return endpoint has moved to another node.
		return fmt.Errorf("Kubernetes pod %s/%s is not owned by this agent", ep.K8sNamespace, ep.K8sPodName)
	}
	return nil
}

// fetchOldEndpoints reads the list of existing endpoints previously managed by Cilium when it was
// last run and associated it with container workloads. This function performs the first step in
// restoring the endpoint structure.  It needs to be followed by a call to restoreOldEndpoints()
// once k8s has been initialized and regenerateRestoredEndpoints() once the endpoint builder is
// ready. In summary:
//
// 1. fetchOldEndpoints(): Unmarshal old endpoints
//   - used to start DNS proxy with restored DNS history and rules
//
// 2. restoreOldEndpoints(): validate endpoint data after k8s has been configured
//   - IP allocation
//   - some endpoints may be rejected and not regnerated in the 3rd step
//
// 3. regenerateRestoredEndpoints(): Regenerate the restored endpoints
//   - recreate endpoint's policy, as well as bpf programs and maps
func (d *Daemon) fetchOldEndpoints(dir string) (*endpointRestoreState, error) {
	state := &endpointRestoreState{
		possible: nil,
		restored: []*endpoint.Endpoint{},
		toClean:  []*endpoint.Endpoint{},
	}

	if !option.Config.RestoreState {
		log.Info("Endpoint restore is disabled, skipping restore step")
		return state, nil
	}

	log.Info("Reading old endpoints...")

	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		return state, err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	state.possible = endpoint.ReadEPsFromDirNames(d.ctx, d, d, d.ipcache, dir, eptsID)

	if len(state.possible) == 0 {
		log.Info("No old endpoints found.")
	}
	return state, nil
}

// restoreOldEndpoints performs the second step in restoring the endpoint structure,
// allocating their existing IPs out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// regenerateRestoredEndpoints() once the endpoint builder is ready.
//
// If clean is true, endpoints which cannot be associated with a container
// workloads are deleted.
func (d *Daemon) restoreOldEndpoints(state *endpointRestoreState, clean bool) error {
	failed := 0
	defer func() {
		state.possible = nil
	}()

	if !option.Config.RestoreState {
		log.Info("Endpoint restore is disabled, skipping restore step")
		return nil
	}

	var emf endpointMetadataFetcher
	if option.Config.EnableHighScaleIPcache {
		emf = &uncachedEndpointMetadataFetcher{slimcli: d.clientset.Slim()}
	} else {
		emf = &cachedEndpointMetadataFetcher{k8sWatcher: d.k8sWatcher}
	}
	d.endpointMetadataFetcher = emf

	log.Info("Restoring endpoints...")

	var (
		existingEndpoints map[string]*lxcmap.EndpointInfo
		err               error
	)

	if !option.Config.DryMode {
		existingEndpoints, err = lxcmap.DumpToMap()
		if err != nil {
			log.WithError(err).Warning("Unable to open endpoint map while restoring. Skipping cleanup of endpoint map on startup")
		}
	}

	for _, ep := range state.possible {
		scopedLog := log.WithField(logfields.EndpointID, ep.ID)
		if d.clientset.IsEnabled() {
			scopedLog = scopedLog.WithField("k8sPodName", ep.GetK8sNamespaceAndPodName())
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
		ep.SetAllocator(d.identityAllocator)

		restore, err := d.validateEndpoint(ep)
		if err != nil {
			// Disconnected EPs are not failures, clean them silently below
			if !ep.IsDisconnecting() {
				d.endpointManager.DeleteK8sCiliumEndpointSync(ep)
				scopedLog.WithError(err).Warningf("Unable to restore endpoint, ignoring")
				failed++
			}
		}
		if !restore {
			if clean {
				state.toClean = append(state.toClean, ep)
			}
			continue
		}

		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOK(endpoint.Other, "Restoring endpoint from previous cilium instance")

		ep.SetDefaultConfiguration(true)
		ep.SetProxy(d.l7Proxy)
		ep.SkipStateClean()

		state.restored = append(state.restored, ep)

		if existingEndpoints != nil {
			delete(existingEndpoints, ep.GetIPv4Address())
			delete(existingEndpoints, ep.GetIPv6Address())
		}
	}

	log.WithFields(logrus.Fields{
		"restored": len(state.restored),
		"failed":   failed,
	}).Info("Endpoints restored")

	if existingEndpoints != nil {
		for epIP, info := range existingEndpoints {
			if ip := net.ParseIP(epIP); !info.IsHost() && ip != nil {
				if err := lxcmap.DeleteEntry(ip); err != nil {
					log.WithError(err).Warn("Unable to delete obsolete endpoint from BPF map")
				} else {
					log.Debugf("Removed outdated endpoint %d from endpoint map", info.LxcID)
				}
			}
		}
	}

	return nil
}

func (d *Daemon) regenerateRestoredEndpoints(state *endpointRestoreState) (restoreComplete chan struct{}) {
	restoreComplete = make(chan struct{}, 0)

	log.WithField("numRestored", len(state.restored)).Info("Regenerating restored endpoints")

	// Before regenerating, check whether the CT map has properties that
	// match this Cilium userspace instance. If not, it must be removed
	ctmap.DeleteIfUpgradeNeeded(nil)

	// we need to signalize when the endpoints are regenerated, i.e., when
	// they have finished to rebuild after being restored.
	epRegenerated := make(chan bool, len(state.restored))

	// Insert all endpoints into the endpoint list first before starting
	// the regeneration. This is required to ensure that if an individual
	// regeneration causes an identity change of an endpoint, the new
	// identity will trigger a policy recalculation of all endpoints to
	// account for the new identity during the grace period. For this
	// purpose, all endpoints being restored must already be in the
	// endpoint list.
	for i := len(state.restored) - 1; i >= 0; i-- {
		ep := state.restored[i]
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
		if err := d.endpointManager.RestoreEndpoint(ep); err != nil {
			log.WithError(err).Warning("Unable to restore endpoint")
			// remove endpoint from slice of endpoints to restore
			state.restored = append(state.restored[:i], state.restored[i+1:]...)
		}
	}

	for _, ep := range state.restored {
		log.WithField(logfields.EndpointID, ep.ID).Info("Successfully restored endpoint. Scheduling regeneration")
		go func(ep *endpoint.Endpoint, epRegenerated chan<- bool) {
			if err := ep.RegenerateAfterRestore(); err != nil {
				log.WithField(logfields.EndpointID, ep.ID).WithError(err).Debug("error regenerating during restore")
				epRegenerated <- false
				return
			}
			epRegenerated <- true
		}(ep, epRegenerated)
	}

	var endpointCleanupCompleted sync.WaitGroup
	for _, ep := range state.toClean {
		endpointCleanupCompleted.Add(1)
		go func(ep *endpoint.Endpoint) {
			// The IP was not allocated yet so does not need to be free.
			// The identity may be allocated in the kvstore but we can't
			// release it easily as it will require to block on kvstore
			// connectivity which we can't do at this point. Let the lease
			// expire to release the identity.
			d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
				NoIdentityRelease: true,
				NoIPRelease:       true,
			})
			endpointCleanupCompleted.Done()
		}(ep)
	}
	endpointCleanupCompleted.Wait()

	go func() {
		regenerated, total := 0, 0
		if len(state.restored) > 0 {
			for buildSuccess := range epRegenerated {
				if buildSuccess {
					regenerated++
				}
				total++
				if total >= len(state.restored) {
					break
				}
			}
		}
		close(epRegenerated)

		log.WithFields(logrus.Fields{
			"regenerated": regenerated,
			"total":       total,
		}).Info("Finished regenerating restored endpoints")
		close(restoreComplete)
	}()

	return
}

func (d *Daemon) allocateIPsLocked(ep *endpoint.Endpoint) (err error) {
	if option.Config.EnableIPv6 && ep.IPv6.IsValid() {
		ipv6Pool := ipam.PoolOrDefault(ep.IPv6IPAMPool)
		_, err = d.ipam.AllocateIPWithoutSyncUpstream(ep.IPv6.AsSlice(), ep.HumanStringLocked()+" [restored]", ipv6Pool)
		if err != nil {
			return fmt.Errorf("unable to reallocate %s IPv6 address: %w", ep.IPv6, err)
		}

		defer func() {
			if err != nil {
				d.ipam.ReleaseIP(ep.IPv6.AsSlice(), ipv6Pool)
			}
		}()
	}

	if option.Config.EnableIPv4 && ep.IPv4.IsValid() {
		ipv4Pool := ipam.PoolOrDefault(ep.IPv4IPAMPool)
		_, err = d.ipam.AllocateIPWithoutSyncUpstream(ep.IPv4.AsSlice(), ep.HumanStringLocked()+" [restored]", ipv4Pool)
		switch {
		// We only check for BypassIPAllocUponRestore for IPv4 because we
		// assume that this flag is only turned on for IPv4-only IPAM modes
		// such as ENI.
		//
		// Additionally, only check for a specific error which can be caused by
		// https://github.com/cilium/cilium/pull/15453. Other errors are not
		// bypassed.
		case err != nil &&
			errors.Is(err, ipam.NewIPNotAvailableInPoolError(ep.IPv4.AsSlice())) &&
			option.Config.BypassIPAvailabilityUponRestore:
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr:     ep.IPv4,
				logfields.EndpointID: ep.ID,
				logfields.K8sPodName: ep.GetK8sNamespaceAndPodName(),
			}).Warn(
				"Bypassing IP not available error on endpoint restore. This is " +
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

func (d *Daemon) initRestore(restoredEndpoints *endpointRestoreState) chan struct{} {
	bootstrapStats.restore.Start()
	var restoreComplete chan struct{}
	if option.Config.RestoreState {
		// When we regenerate restored endpoints, it is guaranteed tha we have
		// received the full list of policies present at the time the daemon
		// is bootstrapped.
		restoreComplete = d.regenerateRestoredEndpoints(restoredEndpoints)
		go func() {
			<-restoreComplete
		}()

		go func() {
			if d.clientset.IsEnabled() {
				// Also wait for all cluster mesh to be synchronized with the
				// datapath before proceeding.
				if d.clustermesh != nil {
					err := d.clustermesh.ClustersSynced(d.ctx)
					if err != nil {
						log.WithError(err).Fatal("timeout while waiting for all clusters to be locally synchronized")
					}
					log.Debug("all clusters have been correctly synchronized locally")
				}
				// Start controller which removes any leftover Kubernetes
				// services that may have been deleted while Cilium was not
				// running. Once this controller succeeds, because it has no
				// RunInterval specified, it will not run again unless updated
				// elsewhere. This means that if, for instance, a user manually
				// adds a service via the CLI into the BPF maps, that it will
				// not be cleaned up by the daemon until it restarts.
				controller.NewManager().UpdateController("sync-lb-maps-with-k8s-services",
					controller.ControllerParams{
						DoFunc: func(ctx context.Context) error {
							return d.svc.SyncWithK8sFinished()
						},
						Context: d.ctx,
					},
				)
			}
		}()
	} else {
		log.Info("State restore is disabled. Existing endpoints on node are ignored")
	}
	bootstrapStats.restore.End(true)

	return restoreComplete
}
