// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var syncLBMapsControllerGroup = controller.NewGroup("sync-lb-maps-with-k8s-services")

func (d *Daemon) WaitForEndpointRestore(ctx context.Context) error {
	if !option.Config.RestoreState {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.endpointRestoreComplete:
	}
	return nil
}

func (d *Daemon) WaitForInitialPolicy(ctx context.Context) error {
	if !option.Config.RestoreState {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.endpointRestoreComplete:
	case <-d.endpointInitialPolicyComplete:
	}
	return nil
}

type endpointRestoreState struct {
	possible map[uint16]*endpoint.Endpoint
	restored []*endpoint.Endpoint
	toClean  []*endpoint.Endpoint
}

// checkLink returns an error if a link with linkName does not exist.
func checkLink(linkName string) error {
	_, err := safenetlink.LinkByName(linkName)
	return err
}

// validateEndpoint attempts to determine that the restored endpoint is valid, ie it
// still exists in k8s, its datapath devices are present, and Cilium is
// responsible for its workload, etc.
//
// Returns true to indicate that the endpoint is valid to restore, and an
// optional error.
func (d *Daemon) validateEndpoint(ep *endpoint.Endpoint) (valid bool, err error) {
	if ep.IsProperty(endpoint.PropertyFakeEndpoint) {
		return true, nil
	}

	// On each restart, the health endpoint is supposed to be recreated.
	// Hence we need to clean health endpoint state unconditionally.
	if ep.HasLabels(labels.LabelHealth) {
		// Ignore health endpoint and don't report
		// it as not restored. But we need to clean up the old
		// state files, so do this now.
		healthStateDir := ep.StateDirectoryPath()
		d.logger.Debug("Removing old health endpoint state directory",
			logfields.EndpointID, ep.ID,
			logfields.Path, healthStateDir,
		)
		if err := os.RemoveAll(healthStateDir); err != nil {
			d.logger.Warn("Cannot clean up old health state directory",
				logfields.EndpointID, ep.ID,
				logfields.Path, healthStateDir,
			)
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
		ep.RunRestoredMetadataResolver(d.endpointMetadata.FetchK8sMetadataForEndpoint)
	}

	if err := ep.ValidateConnectorPlumbing(checkLink); err != nil {
		return false, err
	}

	if !ep.DatapathConfiguration.ExternalIpam {
		if err := d.allocateIPsLocked(ep); err != nil {
			return false, fmt.Errorf("Failed to re-allocate IP of endpoint: %w", err)
		}
	}

	return true, nil
}

func (d *Daemon) getPodForEndpoint(ep *endpoint.Endpoint) error {
	var (
		pod *slim_corev1.Pod
		err error
	)
	d.k8sWatcher.WaitForCacheSync(resources.K8sAPIGroupPodV1Core)
	pod, err = d.k8sWatcher.GetCachedPod(ep.K8sNamespace, ep.K8sPodName)
	if err != nil && k8serrors.IsNotFound(err) {
		return fmt.Errorf("Kubernetes pod %s/%s does not exist", ep.K8sNamespace, ep.K8sPodName)
	} else if err == nil && pod.Spec.NodeName != nodeTypes.GetName() {
		// if flag CiliumEndpointCRD is disabled,
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
		d.logger.Info("Endpoint restore is disabled, skipping restore step")
		return state, nil
	}

	d.logger.Info("Reading old endpoints...")

	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		return state, err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	state.possible = endpoint.ReadEPsFromDirNames(d.ctx, logging.DefaultSlogLogger, d.endpointCreator, dir, eptsID)

	if len(state.possible) == 0 {
		d.logger.Info("No old endpoints found.")
	}
	return state, nil
}

// restoreOldEndpoints performs the second step in restoring the endpoint structure,
// allocating their existing IPs out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// regenerateRestoredEndpoints() once the endpoint builder is ready.
// Endpoints which cannot be associated with a container workload are deleted.
func (d *Daemon) restoreOldEndpoints(state *endpointRestoreState) {
	failed := 0
	defer func() {
		state.possible = nil
	}()

	if !option.Config.RestoreState {
		d.logger.Info("Endpoint restore is disabled, skipping restore step")
		return
	}

	d.logger.Info("Restoring endpoints...")

	var (
		existingEndpoints map[string]lxcmap.EndpointInfo
		err               error
	)

	if !option.Config.DryMode {
		existingEndpoints, err = lxcmap.DumpToMap()
		if err != nil {
			d.logger.Warn("Unable to open endpoint map while restoring. Skipping cleanup of endpoint map on startup", logfields.Error, err)
		}
	}

	for _, ep := range state.possible {
		scopedLog := d.logger.With(logfields.EndpointID, ep.ID)
		if d.clientset.IsEnabled() {
			scopedLog = scopedLog.With(logfields.CEPName, ep.GetK8sNamespaceAndCEPName())
		}

		restore, err := d.validateEndpoint(ep)
		if err != nil {
			// Disconnected EPs are not failures, clean them silently below
			if !ep.IsDisconnecting() {
				d.endpointManager.DeleteK8sCiliumEndpointSync(ep)
				scopedLog.Warn("Unable to restore endpoint, ignoring", logfields.Error, err)
				failed++
			}
		}
		if !restore {
			state.toClean = append(state.toClean, ep)
			continue
		}

		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOK(endpoint.Other, "Restoring endpoint from previous cilium instance")

		ep.SetDefaultConfiguration()
		ep.SkipStateClean()

		state.restored = append(state.restored, ep)

		if existingEndpoints != nil {
			delete(existingEndpoints, ep.GetIPv4Address())
			delete(existingEndpoints, ep.GetIPv6Address())
		}
	}

	d.logger.Info(
		"Endpoints restored",
		logfields.Restored, len(state.restored),
		logfields.Failed, failed,
	)

	for epIP, info := range existingEndpoints {
		if ip := net.ParseIP(epIP); !info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				d.logger.Warn("Unable to delete obsolete endpoint from BPF map", logfields.Error, err)
			} else {
				d.logger.Debug(
					"Removed outdated endpoint from endpoint map",
					logfields.EndpointLXCID, uint64(info.LxcID),
				)
			}
		}
	}
}

func (d *Daemon) regenerateRestoredEndpoints(state *endpointRestoreState, endpointsRegenerator *endpoint.Regenerator) {
	d.logger.Info(
		"Regenerating restored endpoints",
		logfields.Restored, len(state.restored),
	)

	// Before regenerating, check whether the CT map has properties that
	// match this Cilium userspace instance. If not, it must be removed
	ctmap.DeleteIfUpgradeNeeded()

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

		// Insert into endpoint manager so it can be regenerated when calls to
		// RegenerateAllEndpoints() are made. This must be done synchronously (i.e.,
		// not in a goroutine) because regenerateRestoredEndpoints must guarantee
		// upon returning that endpoints are exposed to other subsystems via
		// endpointmanager.
		if err := d.endpointManager.RestoreEndpoint(ep); err != nil {
			d.logger.Warn("Unable to restore endpoint", logfields.Error, err)
			// remove endpoint from slice of endpoints to restore
			state.restored = slices.Delete(state.restored, i, i+1)
		}
	}

	if option.Config.EnableIPSec {
		// To support v1.18 VinE upgrades, we need to restore the host
		// endpoint before any other endpoint, to ensure a drop-less upgrade.
		// This is because in v1.18 'bpf_lxc' programs stop issuing IPsec hooks
		// which trigger encryption.
		//
		// Instead, 'bpf_host' is responsible for performing IPsec hooks.
		// Therefore, we want 'bpf_host' to regenerate BEFORE 'bpf_lxc' so the
		// IPsec hooks are always present while 'bpf_lxc' programs regen,
		// ensuring no IPsec leaks occur.
		//
		// This can be removed in v1.19.
		for _, ep := range state.restored {
			if ep.IsHost() {
				d.logger.Info("Successfully restored endpoint. Scheduling regeneration", logfields.EndpointID, ep.ID)
				if err := ep.RegenerateAfterRestore(endpointsRegenerator, d.endpointMetadata.FetchK8sMetadataForEndpoint); err != nil {
					d.logger.Debug(
						"error regenerating during restore",
						logfields.Error, err,
						logfields.EndpointID, ep.ID,
					)
					epRegenerated <- false
				} else {
					epRegenerated <- true
				}
				break
			}
		}
	}

	for _, ep := range state.restored {
		if ep.IsHost() && option.Config.EnableIPSec {
			// The host endpoint was handled above.
			continue
		}
		d.logger.Info(
			"Successfully restored endpoint. Scheduling regeneration",
			logfields.EndpointID, ep.ID,
		)
		go func(ep *endpoint.Endpoint, epRegenerated chan<- bool) {
			if err := ep.RegenerateAfterRestore(endpointsRegenerator, d.endpointMetadata.FetchK8sMetadataForEndpoint); err != nil {
				d.logger.Debug(
					"error regenerating during restore",
					logfields.Error, err,
					logfields.EndpointID, ep.ID,
				)
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
			d.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{
				NoIdentityRelease: true,
				NoIPRelease:       true,
			})
			endpointCleanupCompleted.Done()
		}(ep)
	}
	endpointCleanupCompleted.Wait()

	go func() {
		for _, ep := range state.restored {
			<-ep.InitialEnvoyPolicyComputed
		}
		close(d.endpointInitialPolicyComplete)
	}()

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

		d.logger.Info(
			"Finished regenerating restored endpoints",
			logfields.Regenerated, regenerated,
			logfields.Total, total,
		)
		close(d.endpointRestoreComplete)
	}()
}

func (d *Daemon) allocateIPsLocked(ep *endpoint.Endpoint) (err error) {
	if option.Config.EnableIPv6 && ep.IPv6.IsValid() {
		ipv6Pool := ipam.PoolOrDefault(ep.IPv6IPAMPool)
		_, err = d.ipam.AllocateIPWithoutSyncUpstream(ep.IPv6.AsSlice(), ep.HumanString()+" [restored]", ipv6Pool)
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
		_, err = d.ipam.AllocateIPWithoutSyncUpstream(ep.IPv4.AsSlice(), ep.HumanString()+" [restored]", ipv4Pool)
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
			d.logger.Warn(
				"Bypassing IP not available error on endpoint restore. This is "+
					"to prevent errors upon Cilium upgrade and should not be "+
					"relied upon. Consider restarting this pod in order to get "+
					"a fresh IP from the pool.",
				logfields.Error, err,
				logfields.IPAddr, ep.IPv4,
				logfields.EndpointID, ep.ID,
				logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
			)
		case err != nil:
			return fmt.Errorf("unable to reallocate %s IPv4 address: %w", ep.IPv4, err)
		}
	}

	return nil
}

func (d *Daemon) initRestore(restoredEndpoints *endpointRestoreState, endpointsRegenerator *endpoint.Regenerator) {
	bootstrapStats.restore.Start()
	if option.Config.RestoreState {
		// When we regenerate restored endpoints, it is guaranteed that we have
		// received the full list of policies present at the time the daemon
		// is bootstrapped.
		d.regenerateRestoredEndpoints(restoredEndpoints, endpointsRegenerator)

		go func() {
			if d.clientset.IsEnabled() {
				// Configure the controller which removes any leftover Kubernetes
				// services that may have been deleted while Cilium was not
				// running. Once this controller succeeds, because it has no
				// RunInterval specified, it will not run again unless updated
				// elsewhere. This means that if, for instance, a user manually
				// adds a service via the CLI into the BPF maps, it will
				// not be cleaned up by the daemon until it restarts.
				syncServices := func(localOnly bool) {
					d.controllers.UpdateController(
						"sync-lb-maps-with-k8s-services",
						controller.ControllerParams{
							Group: syncLBMapsControllerGroup,
							DoFunc: func(ctx context.Context) error {
								var localServices sets.Set[k8s.ServiceID]
								if localOnly {
									localServices = d.k8sSvcCache.LocalServices()
								}

								stale, err := d.svc.SyncWithK8sFinished(localOnly, localServices)

								// Always process the list of stale services, regardless
								// of whether an error was returned.
								swg := lock.NewStoppableWaitGroup()
								for _, svc := range stale {
									d.k8sSvcCache.EnsureService(svc, swg)
									if option.Config.EnableLocalRedirectPolicy {
										d.lrpManager.EnsureService(svc)
									}
								}

								swg.Stop()
								swg.Wait()

								return err
							},
							Context: d.ctx,
						},
					)
				}

				// Also wait for all shared services to be synchronized with the
				// datapath before proceeding.
				if d.clustermesh != nil {
					// Do a first pass synchronizing only the services which are not
					// marked as global, so that we can drop their stale backends
					// without needing to wait for full clustermesh synchronization.
					syncServices(true /* only local services */)

					err := d.clustermesh.ServicesSynced(d.ctx)
					if err != nil {
						return // The parent context expired, and we are already terminating
					}
					d.logger.Debug("all clusters have been correctly synchronized locally")
				}

				// Now that possible global services have also been synchronized, let's
				// do a final pass to remove the remaining stale services and backends.
				syncServices(false /* all services */)
			}
		}()
	} else {
		d.logger.Info("State restore is disabled. Existing endpoints on node are ignored")
	}
	bootstrapStats.restore.End(true)
}
