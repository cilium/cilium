// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/daemon/cmd/legacy"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	policyDirectory "github.com/cilium/cilium/pkg/policy/directory"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// endpointRestore cell provides the logic to restore the endpoints at agent startup.
var endpointRestoreCell = cell.Module(
	"endpoint-restore",
	"Initial endpoint restoration at agent startup",

	cell.Provide(promise.New[endpointstate.Restorer]),
	cell.Provide(newEndpointRestorer),
	cell.Invoke(registerEndpointRestoreFinishJob),
	metrics.Metric(newEndpointRestoreMetrics),
)

// registerEndpointRestoreFinishJob registers a hive job that asynchronously performs the last step of the endpoint restoration
// (expose the restored endpoints via endpointmanager & trigger regeneration).
//
// The first two steps of the endpoint restoration are still explicitly initiated by the legacy startup logic (configureDaemon) -
// therefore this cell needs to depend on legacy.DaemonInitialization.
// For the same reason, the job can't be registered by newEndpointRestorer cell (would result in circular dependencies)
func registerEndpointRestoreFinishJob(jobGroup job.Group, endpointRestorer *endpointRestorer, _ legacy.DaemonInitialization) {
	if option.Config.DryMode {
		return
	}

	jobGroup.Add(job.OneShot("finish-endpoint-restore", endpointRestorer.InitRestore, job.WithShutdown()))
}

type endpointRestorerParams struct {
	cell.In

	Resolver             promise.Resolver[endpointstate.Restorer]
	RestorationNotifiers []endpointstate.RestorationNotifier `group:"endpointRestorationNotifiers"`

	Lifecycle           cell.Lifecycle
	DaemonConfig        *option.DaemonConfig
	Logger              *slog.Logger
	Metrics             *endpointRestoreMetrics
	K8sWatcher          *watchers.K8sWatcher
	Clientset           k8sClient.Clientset
	EndpointCreator     endpointcreator.EndpointCreator
	EndpointManager     endpointmanager.EndpointManager
	EndpointRegenerator *endpoint.Regenerator
	EndpointMetadata    endpointmetadata.EndpointMetadataFetcher
	EndpointAPIFence    endpointapi.Fence
	IPSecAgent          datapath.IPsecAgent
	IPAMManager         *ipam.IPAM
	CacheStatus         k8sSynced.CacheStatus
	DirReadStatus       policyDirectory.DirectoryWatcherReadStatus
	IPCache             *ipcache.IPCache
	LXCMap              lxcmap.Map
	ConnectorConfig     datapath.ConnectorConfig
}

type endpointRestorer struct {
	logger              *slog.Logger
	stateDir            string
	k8sWatcher          *watchers.K8sWatcher
	clientset           k8sClient.Clientset
	endpointCreator     endpointcreator.EndpointCreator
	endpointManager     endpointmanager.EndpointManager
	endpointRegenerator *endpoint.Regenerator
	endpointMetadata    endpointmetadata.EndpointMetadataFetcher
	endpointAPIFence    endpointapi.Fence
	ipSecAgent          datapath.IPsecAgent
	ipamManager         *ipam.IPAM
	lxcMap              lxcmap.Map
	connectorConfig     datapath.ConnectorConfig

	cacheStatus   k8sSynced.CacheStatus
	dirReadStatus policyDirectory.DirectoryWatcherReadStatus
	ipCache       *ipcache.IPCache

	restoreState                  *endpointRestoreState
	metrics                       *endpointRestoreMetrics
	endpointRestoreComplete       chan struct{}
	endpointRegenerateComplete    chan struct{}
	endpointInitialPolicyComplete chan struct{}
}

func newEndpointRestorer(params endpointRestorerParams) *endpointRestorer {
	restorer := &endpointRestorer{
		logger:              params.Logger,
		stateDir:            params.DaemonConfig.StateDir,
		k8sWatcher:          params.K8sWatcher,
		clientset:           params.Clientset,
		endpointCreator:     params.EndpointCreator,
		endpointManager:     params.EndpointManager,
		endpointRegenerator: params.EndpointRegenerator,
		endpointMetadata:    params.EndpointMetadata,
		endpointAPIFence:    params.EndpointAPIFence,
		ipSecAgent:          params.IPSecAgent,
		ipamManager:         params.IPAMManager,
		lxcMap:              params.LXCMap,
		connectorConfig:     params.ConnectorConfig,

		cacheStatus:   params.CacheStatus,
		dirReadStatus: params.DirReadStatus,
		ipCache:       params.IPCache,

		metrics:                       params.Metrics,
		endpointRestoreComplete:       make(chan struct{}),
		endpointRegenerateComplete:    make(chan struct{}),
		endpointInitialPolicyComplete: make(chan struct{}),
		restoreState: &endpointRestoreState{
			possible: nil,
			restored: []*endpoint.Endpoint{},
			toClean:  []*endpoint.Endpoint{},
		},
	}

	// Restorer promise is still required to avoid circular dependencies -
	// but we can immediately resolve it.
	params.Resolver.Resolve(restorer)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if err := restorer.clearStaleCiliumEndpointVeths(); err != nil {
				// log and continue
				params.Logger.Warn("Unable to clean stale endpoint interfaces", logfields.Error, err)
			}

			// read old endpoints from disk before k8s is configured
			if err := restorer.readOldEndpointsFromDisk(ctx); err != nil {
				params.Logger.Error("Unable to read existing endpoints", logfields.Error, err)
			}

			params.Logger.Debug("Notify endpoint restoration notifiers about restored endpoints", logfields.Registrations, len(params.RestorationNotifiers))
			for _, r := range params.RestorationNotifiers {
				if r != nil {
					r.RestorationNotify(restorer.restoreState.possible)
				}
			}

			return nil
		},
	})

	return restorer
}

func (r *endpointRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	if !option.Config.RestoreState {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.endpointRestoreComplete:
	}
	return nil
}

func (r *endpointRestorer) WaitForEndpointRestore(ctx context.Context) error {
	if !option.Config.RestoreState {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.endpointRegenerateComplete:
	}
	return nil
}

func (r *endpointRestorer) WaitForInitialPolicy(ctx context.Context) error {
	if !option.Config.RestoreState {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.endpointRegenerateComplete:
	case <-r.endpointInitialPolicyComplete:
	}
	return nil
}

type endpointRestoreState struct {
	possible map[uint16]*endpoint.Endpoint
	restored []*endpoint.Endpoint
	toClean  []*endpoint.Endpoint
}

// checkLink returns an error if a link with linkName does not exist.
func (r *endpointRestorer) checkLink(linkName string) error {
	_, err := safenetlink.LinkByName(linkName)
	return err
}

// validateDatapathModeCompatibility checks if endpoints being restored are compatible
// with the current datapath mode. If the agent is configured with netkit/veth mode and
// detects existing endpoints using veth/netkit, it will exit with a fatal error describing
// the compatibility issue
func (r *endpointRestorer) validateDatapathModeCompatibility(endpoints map[uint16]*endpoint.Endpoint) error {
	var incompatibleEndpoints []string
	var incompatibleTypes []string

	for _, ep := range endpoints {
		// Only check pod endpoints, skip host endpoint, health endpoint, and other special endpoints
		if !ep.K8sNamespaceAndPodNameIsSet() {
			continue
		}

		// Skip fake endpoints
		if ep.IsProperty(endpoint.PropertyFakeEndpoint) {
			continue
		}

		ifName := ep.HostInterface()
		linkMode, linkCompat, err := r.connectorConfig.GetLinkCompatibility(ifName)
		if err != nil {
			r.logger.Debug("Failed to check endpoint link type, skipping",
				logfields.EndpointID, ep.ID,
				logfields.Error, err,
			)
			continue
		}
		if !linkCompat {
			epName := fmt.Sprintf("%s/%s (endpoint-%d)", ep.K8sNamespace, ep.K8sPodName, ep.ID)
			incompatibleEndpoints = append(incompatibleEndpoints, epName)

			linkModeName := linkMode.String()
			if !slices.Contains(incompatibleTypes, linkModeName) {
				incompatibleTypes = append(incompatibleTypes, linkModeName)
			}
		}
	}

	if len(incompatibleEndpoints) > 0 {
		currentDatapathMode := r.connectorConfig.GetOperationalMode().String()
		return fmt.Errorf(
			"Cannot start cilium-agent with datapath-mode=%s: detected %d existing endpoint(s) using incompatible datapath-modes. "+
				"Affected endpoints: %s. "+
				"Detected incompatible datapath-modes: %s. "+
				"Please delete these pods or correct the cilium-agent operational datapath-mode.",
			currentDatapathMode, len(incompatibleEndpoints),
			strings.Join(incompatibleEndpoints, ", "),
			strings.Join(incompatibleTypes, ", "))
	}

	return nil
}

// validateEndpoint attempts to determine that the restored endpoint is valid, ie it
// still exists in k8s, its datapath devices are present, and Cilium is
// responsible for its workload, etc.
//
// Returns true to indicate that the endpoint is valid to restore, and an
// optional error.
func (r *endpointRestorer) validateEndpoint(ep *endpoint.Endpoint) (valid bool, err error) {
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
		r.logger.Debug("Removing old health endpoint state directory",
			logfields.EndpointID, ep.ID,
			logfields.Path, healthStateDir,
		)
		if err := os.RemoveAll(healthStateDir); err != nil {
			r.logger.Warn("Cannot clean up old health state directory",
				logfields.EndpointID, ep.ID,
				logfields.Path, healthStateDir,
			)
		}
		return false, nil
	}

	if ep.K8sPodName != "" && ep.K8sNamespace != "" && r.clientset.IsEnabled() {
		if err := r.getPodForEndpoint(ep); err != nil {
			return false, err
		}

		// Initialize the endpoint's event queue because the following call to
		// execute the metadata resolver will emit events for the endpoint.
		// After this endpoint is validated, it'll eventually be restored, in
		// which the endpoint manager will begin processing the events off the
		// queue.
		ep.InitEventQueue()
		ep.RunRestoredMetadataResolver(r.endpointMetadata.FetchK8sMetadataForEndpoint)
	}

	if err := ep.ValidateConnectorPlumbing(r.checkLink); err != nil {
		return false, err
	}

	if !ep.DatapathConfiguration.ExternalIpam {
		if err := r.allocateIPsLocked(ep); err != nil {
			return false, fmt.Errorf("Failed to re-allocate IP of endpoint: %w", err)
		}
	}

	return true, nil
}

func (r *endpointRestorer) getPodForEndpoint(ep *endpoint.Endpoint) error {
	var (
		pod *slim_corev1.Pod
		err error
	)
	r.k8sWatcher.WaitForCacheSync(resources.K8sAPIGroupPodV1Core)
	pod, err = r.k8sWatcher.GetCachedPod(ep.K8sNamespace, ep.K8sPodName)
	if err != nil && k8serrors.IsNotFound(err) {
		return fmt.Errorf("Kubernetes pod %s/%s does not exist", ep.K8sNamespace, ep.K8sPodName)
	} else if err == nil && pod.Spec.NodeName != nodeTypes.GetName() {
		// if flag CiliumEndpointCRD is disabled,
		// `GetCachedPod` may return endpoint has moved to another node.
		return fmt.Errorf("Kubernetes pod %s/%s is not owned by this agent", ep.K8sNamespace, ep.K8sPodName)
	}
	return nil
}

// readOldEndpointsFromDisk reads the list of existing endpoints previously managed by Cilium when it was
// last run and associated it with container workloads. This function performs the first step in
// restoring the endpoint structure.  It needs to be followed by a call to restoreOldEndpoints()
// once k8s has been initialized and regenerateRestoredEndpoints() once the endpoint builder is
// ready. In summary:
//
// 1. readOldEndpointFromDisk(): read old endpoints from disk
//   - used to start DNS proxy with restored DNS history and rules
//
// 2. restoreOldEndpoints(): validate endpoint data after k8s has been configured
//   - IP allocation
//   - some endpoints may be rejected and not regenerated in the 3rd step
//
// 3. regenerateRestoredEndpoints(): Regenerate the restored endpoints
//   - recreate endpoint's policy, as well as bpf programs and maps
func (r *endpointRestorer) readOldEndpointsFromDisk(ctx context.Context) error {
	if !option.Config.RestoreState {
		r.logger.Info("Endpoint restore is disabled, skipping restore step")
		return nil
	}

	var failed int

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		r.metrics.Duration.WithLabelValues(phaseRead).Set(d.Seconds())
		r.metrics.Endpoints.WithLabelValues(phaseRead, outcomeTotal).Set(float64(len(r.restoreState.possible) + failed))
		r.metrics.Endpoints.WithLabelValues(phaseRead, outcomeSuccessful).Set(float64(len(r.restoreState.possible)))
		r.metrics.Endpoints.WithLabelValues(phaseRead, outcomeFailed).Set(float64(failed))
	}()

	r.logger.Info("Reading old endpoints...")

	dirFiles, err := os.ReadDir(r.stateDir)
	if err != nil {
		return err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	r.restoreState.possible, failed = endpoint.ReadEPsFromDirNames(ctx, r.logger, r.endpointCreator, r.stateDir, eptsID)

	if len(r.restoreState.possible) == 0 {
		r.logger.Info("No old endpoints found.")
	}

	return nil
}

// restoreOldEndpoints performs the second step in restoring the endpoint structure,
// allocating their existing IPs out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// regenerateRestoredEndpoints() once the endpoint builder is ready.
// Endpoints which cannot be associated with a container workload are deleted.
func (r *endpointRestorer) RestoreOldEndpoints() error {
	failed := 0
	skipped := 0
	defer func() {
		r.restoreState.possible = nil
	}()

	if !option.Config.RestoreState {
		r.logger.Info("Endpoint restore is disabled, skipping restore step")
		return nil
	}

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		r.metrics.Duration.WithLabelValues(phaseRestoration).Set(d.Seconds())
		r.metrics.Endpoints.WithLabelValues(phaseRestoration, outcomeTotal).Set(float64(len(r.restoreState.possible)))
		r.metrics.Endpoints.WithLabelValues(phaseRestoration, outcomeSuccessful).Set(float64(len(r.restoreState.restored)))
		r.metrics.Endpoints.WithLabelValues(phaseRestoration, outcomeSkipped).Set(float64(skipped))
		r.metrics.Endpoints.WithLabelValues(phaseRestoration, outcomeFailed).Set(float64(failed))
	}()

	r.logger.Info("Restoring endpoints...")

	// Validate that endpoints are compatible with the current datapath mode
	if err := r.validateDatapathModeCompatibility(r.restoreState.possible); err != nil {
		return err
	}

	var (
		existingEndpoints map[netip.Addr]lxcmap.EndpointInfo
		err               error
	)

	if !option.Config.DryMode {
		existingEndpoints, err = r.lxcMap.DumpToMap()
		if err != nil {
			r.logger.Warn("Unable to open endpoint map while restoring. Skipping cleanup of endpoint map on startup", logfields.Error, err)
		}
	}

	for _, ep := range r.restoreState.possible {
		scopedLog := r.logger.With(logfields.EndpointID, ep.ID)
		if r.clientset.IsEnabled() {
			scopedLog = scopedLog.With(logfields.CEPName, ep.GetK8sNamespaceAndCEPName())
		}

		restore, err := r.validateEndpoint(ep)
		if err != nil {
			// Disconnected EPs are not failures, clean them silently below
			if !ep.IsDisconnecting() {
				r.endpointManager.DeleteK8sCiliumEndpointSync(ep)
				scopedLog.Warn("Unable to restore endpoint, ignoring", logfields.Error, err)
				failed++
			} else {
				skipped++
			}
		}
		if !restore {
			if err == nil {
				skipped++
			}
			r.restoreState.toClean = append(r.restoreState.toClean, ep)
			continue
		}

		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOK(endpoint.Other, "Restoring endpoint from previous cilium instance")

		ep.SetDefaultConfiguration()
		ep.SkipStateClean()

		r.restoreState.restored = append(r.restoreState.restored, ep)

		if existingEndpoints != nil {
			delete(existingEndpoints, ep.IPv4Address())
			delete(existingEndpoints, ep.IPv6Address())
		}
	}

	r.logger.Info(
		"Endpoints restored",
		logfields.Restored, len(r.restoreState.restored),
		logfields.Failed, failed,
	)

	for addr, info := range existingEndpoints {
		if addr.IsValid() && !info.IsHost() {
			if err := r.lxcMap.DeleteEntry(addr); err != nil {
				r.logger.Warn("Unable to delete obsolete endpoint from BPF map",
					logfields.IPAddr, addr,
					logfields.Error, err,
				)
			} else {
				r.logger.Debug(
					"Removed outdated endpoint from endpoint map",
					logfields.EndpointLXCID, uint64(info.LxcID),
				)
			}
		}
	}

	return nil
}

func (r *endpointRestorer) regenerateRestoredEndpoints(state *endpointRestoreState) {
	r.logger.Info(
		"Regenerating restored endpoints",
		logfields.Restored, len(state.restored),
	)

	// Insert all endpoints into the endpoint list first before starting
	// the regeneration. This is required to ensure that if an individual
	// regeneration causes an identity change of an endpoint, the new
	// identity will trigger a policy recalculation of all endpoints to
	// account for the new identity during the grace period. For this
	// purpose, all endpoints being restored must already be in the
	// endpoint list.
	startTimeRestore := time.Now()
	for i := len(state.restored) - 1; i >= 0; i-- {
		ep := state.restored[i]

		// Insert into endpoint manager so it can be regenerated when calls to
		// RegenerateAllEndpoints() are made. This must be done synchronously (i.e.,
		// not in a goroutine) because regenerateRestoredEndpoints must guarantee
		// upon returning that endpoints are exposed to other subsystems via
		// endpointmanager.
		if err := r.endpointManager.RestoreEndpoint(ep); err != nil {
			r.logger.Warn("Unable to restore endpoint", logfields.Error, err)
			// remove endpoint from slice of endpoints to restore
			state.restored = slices.Delete(state.restored, i, i+1)
		}
	}

	r.logger.Debug(
		"Successfully restored endpoints into endpoint manager",
		logfields.Endpoints, len(state.restored),
		logfields.Duration, time.Since(startTimeRestore),
	)

	startTimeCleanup := time.Now()
	var endpointCleanupCompleted sync.WaitGroup
	for _, ep := range state.toClean {
		endpointCleanupCompleted.Add(1)
		go func(ep *endpoint.Endpoint) {
			// The IP was not allocated yet so does not need to be free.
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

	r.logger.Debug(
		"Successfully cleaned up endpoints that weren't possible to restore",
		logfields.Endpoints, len(state.toClean),
		logfields.Duration, time.Since(startTimeCleanup),
	)

	// Trigger regeneration for relevant restored endpoints in a separate goroutine.
	go r.handleRestoredEndpointsRegeneration(state.restored)

	go func() {
		startTime := time.Now()
		defer func() {
			d := time.Since(startTime)
			r.metrics.Duration.WithLabelValues(phasePolicyComputation).Set(d.Seconds())
			r.metrics.Endpoints.WithLabelValues(phasePolicyComputation, outcomeTotal).Set(float64(len(state.restored)))
			r.metrics.Endpoints.WithLabelValues(phasePolicyComputation, outcomeSuccessful).Set(float64(len(state.restored)))
		}()

		for _, ep := range state.restored {
			ep.WaitForInitialPolicy()
		}
		close(r.endpointInitialPolicyComplete)
	}()
}

// Trigger asynchronous regeneration of restored endpoints.
//
// This method assumes that all the endpoints for which regeneration is requested are
// already exposed to EndpointManager. It waits until the Endpoint API fence is unblocked
// before regenerating all remaining live endpoints.
//
// Once complete, this method closes the daemon 'endpointRestoreComplete' channel.
func (r *endpointRestorer) handleRestoredEndpointsRegeneration(endpoints []*endpoint.Endpoint) {
	total, regenerated, failed := 0, 0, 0

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		r.metrics.Duration.WithLabelValues(phaseRegeneration).Set(d.Seconds())
		r.metrics.Endpoints.WithLabelValues(phaseRegeneration, outcomeTotal).Set(float64(total))
		r.metrics.Endpoints.WithLabelValues(phaseRegeneration, outcomeSuccessful).Set(float64(regenerated))
		r.metrics.Endpoints.WithLabelValues(phaseRegeneration, outcomeFailed).Set(float64(failed))
	}()

	// Wait for Endpoint DeletionQueue to be processed first so we can avoid
	// expensive regeneration for already deleted endpoints.
	_ = r.endpointAPIFence.Wait(context.Background())

	r.logger.Debug(
		"Endpoint API fence unblocked, attempting regeneration for alive endpoints",
		logfields.Duration, time.Since(startTime),
	)

	regenWg := &sync.WaitGroup{}
	epRegenerated := make(chan bool, len(endpoints))

	for _, ep := range endpoints {
		// Check if the endpoint still exists in EndpointManager.
		epFromLookup := r.endpointManager.LookupCiliumID(ep.ID)
		if epFromLookup == nil {
			r.logger.Debug(
				"Endpoint missing in EndpointManager, assuming already deleted",
				logfields.EndpointID, ep.ID,
			)
			continue
		}

		r.logger.Info("Scheduling restored endpoint regeneration", logfields.EndpointID, ep.ID)

		regenWg.Add(1)
		go func(ep *endpoint.Endpoint, wg *sync.WaitGroup, endpointsRegenerated chan<- bool) {
			defer wg.Done()

			if err := ep.RegenerateAfterRestore(r.endpointRegenerator, r.endpointMetadata.FetchK8sMetadataForEndpoint); err != nil {
				r.logger.Debug(
					"Error regenerating endpoint during restore",
					logfields.Error, err,
					logfields.EndpointID, ep.ID,
				)
				endpointsRegenerated <- false
			} else {
				endpointsRegenerated <- true
			}
		}(ep, regenWg, epRegenerated)
	}

	regenWg.Wait()
	close(epRegenerated)

	for buildSuccess := range epRegenerated {
		total++
		if buildSuccess {
			regenerated++
		} else {
			failed++
		}
	}

	r.logger.Info(
		"Finished regenerating restored endpoints",
		logfields.Regenerated, regenerated,
		logfields.Failed, failed,
		logfields.Total, total,
	)
	close(r.endpointRegenerateComplete)
}

func (r *endpointRestorer) allocateIPsLocked(ep *endpoint.Endpoint) (err error) {
	if option.Config.EnableIPv6 && ep.IPv6.IsValid() {
		ipv6Pool := ipam.PoolOrDefault(ep.IPv6IPAMPool)
		_, err = r.ipamManager.AllocateIPWithoutSyncUpstream(ep.IPv6.AsSlice(), ep.HumanString()+" [restored]", ipv6Pool)
		if err != nil {
			return fmt.Errorf("unable to reallocate %s IPv6 address: %w", ep.IPv6, err)
		}

		defer func() {
			if err != nil {
				r.ipamManager.ReleaseIP(ep.IPv6.AsSlice(), ipv6Pool)
			}
		}()
	}

	if option.Config.EnableIPv4 && ep.IPv4.IsValid() {
		ipv4Pool := ipam.PoolOrDefault(ep.IPv4IPAMPool)
		_, err = r.ipamManager.AllocateIPWithoutSyncUpstream(ep.IPv4.AsSlice(), ep.HumanString()+" [restored]", ipv4Pool)
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
			r.logger.Warn(
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

func (r *endpointRestorer) InitRestore(ctx context.Context, health cell.Health) error {
	if !option.Config.RestoreState {
		health.OK("Skipped - state restore is disabled")
		r.logger.Info("State restore is disabled. Existing endpoints on node are ignored")
		return nil
	}

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		r.metrics.Duration.WithLabelValues(phasePrepareRegeneration).Set(d.Seconds())
		r.metrics.Endpoints.WithLabelValues(phasePrepareRegeneration, outcomeTotal).Set(float64(len(r.restoreState.restored)))
		r.metrics.Endpoints.WithLabelValues(phasePrepareRegeneration, outcomeSuccessful).Set(float64(len(r.restoreState.restored)))
	}()

	health.OK("Waiting for K8s initialization")
	// Wait only for certain caches, but not all!
	// (Check K8sWatcher.InitK8sSubsystem() for more info)
	select {
	case <-r.cacheStatus:
	case <-ctx.Done():
		return ctx.Err()
	}

	// wait for directory watcher to ingest policy from files
	health.OK("Waiting for directory watcher to ingest policies from files")
	r.dirReadStatus.Wait()

	// After K8s caches have been synced, IPCache can start label injection.
	// Ensure that the initial labels are injected before we regenerate endpoints
	health.OK("Waiting for initial IPCache revision")
	r.logger.Debug("Waiting for initial IPCache revision")
	if err := r.ipCache.WaitForRevision(ctx, 1); err != nil {
		return fmt.Errorf("failed to wait for initial IPCache revision: %w", err)
	}

	// When we regenerate restored endpoints, it is guaranteed that we have
	// received the full list of policies present at the time the daemon
	// is bootstrapped.
	health.OK("Regenerating restored endpoints")
	r.regenerateRestoredEndpoints(r.restoreState)

	close(r.endpointRestoreComplete)

	return nil
}

// clearStaleCiliumEndpointVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func (r *endpointRestorer) clearStaleCiliumEndpointVeths() error {
	r.logger.Info("Removing stale endpoint interfaces")

	vethIfaces, err := r.listVethIfaces()
	if err != nil {
		return fmt.Errorf("unable to retrieve veth interfaces on host: %w", err)
	}

	for _, v := range vethIfaces {
		peerIndex := v.Attrs().ParentIndex
		peerVeth, peerFoundInHostNamespace := vethIfaces[peerIndex]

		// In addition to name matching, double check whether the parent of the
		// parent is the interface itself, to avoid removing the interface in
		// case we hit an index clash, and the actual parent of the interface is
		// in a different network namespace. Notably, this can happen in the
		// context of Kind nodes, as eth0 is a veth interface itself; if an
		// lxcxxxxxx interface ends up having the same ifindex of the eth0 parent
		// (which is actually located in the root network namespace), we would
		// otherwise end up deleting the eth0 interface, with the obvious
		// ill-fated consequences.
		if peerFoundInHostNamespace &&
			peerIndex != 0 &&
			strings.HasPrefix(peerVeth.Attrs().Name, "lxc") &&
			peerVeth.Attrs().ParentIndex == v.Attrs().Index {

			scopedLog := r.logger.With(
				logfields.Index, v.Attrs().Index,
				logfields.Device, v.Attrs().Name,
			)

			scopedLog.Debug("Deleting stale veth device")

			if err := netlink.LinkDel(v); err != nil {
				scopedLog.Warn("Unable to delete stale veth device", logfields.Error, err)
			}
		}
	}

	return nil
}

// listVethIfaces returns a map of VETH interfaces with the index as key.
func (*endpointRestorer) listVethIfaces() (map[int]netlink.Link, error) {
	ifs, err := safenetlink.LinkList()
	if err != nil {
		return nil, err
	}

	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if intf.Type() == "veth" {
			vethLXCIdxs[intf.Attrs().Index] = intf
		}
	}

	return vethLXCIdxs, nil
}
