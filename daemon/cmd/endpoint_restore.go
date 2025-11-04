// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type endpointRestorerParams struct {
	cell.In

	Logger              *slog.Logger
	K8sWatcher          *watchers.K8sWatcher
	Clientset           k8sClient.Clientset
	EndpointCreator     endpointcreator.EndpointCreator
	EndpointManager     endpointmanager.EndpointManager
	EndpointRegenerator *endpoint.Regenerator
	EndpointMetadata    endpointmetadata.EndpointMetadataFetcher
	EndpointAPIFence    endpointapi.Fence
	IPSecAgent          datapath.IPsecAgent
	IPAMManager         *ipam.IPAM
}

type endpointRestorer struct {
	logger              *slog.Logger
	k8sWatcher          *watchers.K8sWatcher
	clientset           k8sClient.Clientset
	endpointCreator     endpointcreator.EndpointCreator
	endpointManager     endpointmanager.EndpointManager
	endpointRegenerator *endpoint.Regenerator
	endpointMetadata    endpointmetadata.EndpointMetadataFetcher
	endpointAPIFence    endpointapi.Fence
	ipSecAgent          datapath.IPsecAgent
	ipamManager         *ipam.IPAM

	restoreState                  *endpointRestoreState
	endpointRestoreComplete       chan struct{}
	endpointRegenerateComplete    chan struct{}
	endpointInitialPolicyComplete chan struct{}
}

func newEndpointRestorer(params endpointRestorerParams) *endpointRestorer {
	return &endpointRestorer{
		logger:              params.Logger,
		k8sWatcher:          params.K8sWatcher,
		clientset:           params.Clientset,
		endpointCreator:     params.EndpointCreator,
		endpointManager:     params.EndpointManager,
		endpointRegenerator: params.EndpointRegenerator,
		endpointMetadata:    params.EndpointMetadata,
		endpointAPIFence:    params.EndpointAPIFence,
		ipSecAgent:          params.IPSecAgent,
		ipamManager:         params.IPAMManager,

		endpointRestoreComplete:       make(chan struct{}),
		endpointRegenerateComplete:    make(chan struct{}),
		endpointInitialPolicyComplete: make(chan struct{}),
		restoreState: &endpointRestoreState{
			possible: nil,
			restored: []*endpoint.Endpoint{},
			toClean:  []*endpoint.Endpoint{},
		},
	}
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
	var incompatibleType string

	// Determine what type of endpoints are incompatible with current mode
	currentDatapathMode := option.Config.DatapathMode
	isNetkitMode := currentDatapathMode == datapathOption.DatapathModeNetkit || currentDatapathMode == datapathOption.DatapathModeNetkitL2
	isVethMode := currentDatapathMode == datapathOption.DatapathModeVeth

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
		link, err := safenetlink.LinkByName(ifName)
		if err != nil {
			r.logger.Debug("Failed to check endpoint link type, skipping",
				logfields.EndpointID, ep.ID,
				logfields.Error, err,
			)
			continue
		}

		// Check for incompatibility
		isIncompatible := false
		if isNetkitMode && link.Type() == "veth" {
			isIncompatible = true
			incompatibleType = "veth"
		} else if isVethMode && link.Type() == "netkit" {
			isIncompatible = true
			incompatibleType = "netkit"
		}

		if isIncompatible {
			epName := fmt.Sprintf("%s/%s (endpoint-%d)", ep.K8sNamespace, ep.K8sPodName, ep.ID)
			incompatibleEndpoints = append(incompatibleEndpoints, epName)
		}
	}

	if len(incompatibleEndpoints) > 0 {
		return fmt.Errorf(
			"Cannot start cilium-agent with datapath-mode=%s: detected %d existing endpoint(s) using %s datapath mode. "+
				"Endpoints using %s datapath mode: %v. "+
				"Please delete these pods or change the datapath mode back to %s before starting the agent with %s mode",
			currentDatapathMode, len(incompatibleEndpoints), incompatibleType, incompatibleType, incompatibleEndpoints, incompatibleType, currentDatapathMode)
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
//   - some endpoints may be rejected and not regenerated in the 3rd step
//
// 3. regenerateRestoredEndpoints(): Regenerate the restored endpoints
//   - recreate endpoint's policy, as well as bpf programs and maps
func (r *endpointRestorer) FetchOldEndpoints(ctx context.Context, dir string) error {
	if !option.Config.RestoreState {
		r.logger.Info("Endpoint restore is disabled, skipping restore step")
		return nil
	}

	r.logger.Info("Reading old endpoints...")

	dirFiles, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	r.restoreState.possible = endpoint.ReadEPsFromDirNames(ctx, r.logger, r.endpointCreator, dir, eptsID)

	if len(r.restoreState.possible) == 0 {
		r.logger.Info("No old endpoints found.")
	}
	return nil
}

func (r *endpointRestorer) GetState() *endpointRestoreState {
	return r.restoreState
}

// restoreOldEndpoints performs the second step in restoring the endpoint structure,
// allocating their existing IPs out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// regenerateRestoredEndpoints() once the endpoint builder is ready.
// Endpoints which cannot be associated with a container workload are deleted.
func (r *endpointRestorer) RestoreOldEndpoints() error {
	failed := 0
	defer func() {
		r.restoreState.possible = nil
	}()

	if !option.Config.RestoreState {
		r.logger.Info("Endpoint restore is disabled, skipping restore step")
		return nil
	}

	r.logger.Info("Restoring endpoints...")

	// Validate that endpoints are compatible with the current datapath mode
	if err := r.validateDatapathModeCompatibility(r.restoreState.possible); err != nil {
		return err
	}

	var (
		existingEndpoints map[string]lxcmap.EndpointInfo
		err               error
	)

	if !option.Config.DryMode {
		existingEndpoints, err = lxcmap.DumpToMap()
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
			}
		}
		if !restore {
			r.restoreState.toClean = append(r.restoreState.toClean, ep)
			continue
		}

		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOK(endpoint.Other, "Restoring endpoint from previous cilium instance")

		ep.SetDefaultConfiguration()
		ep.SkipStateClean()

		r.restoreState.restored = append(r.restoreState.restored, ep)

		if existingEndpoints != nil {
			delete(existingEndpoints, ep.GetIPv4Address())
			delete(existingEndpoints, ep.GetIPv6Address())
		}
	}

	r.logger.Info(
		"Endpoints restored",
		logfields.Restored, len(r.restoreState.restored),
		logfields.Failed, failed,
	)

	for epIP, info := range existingEndpoints {
		if ip := net.ParseIP(epIP); !info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				r.logger.Warn("Unable to delete obsolete endpoint from BPF map", logfields.Error, err)
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

	// Before regenerating, check whether the CT map has properties that
	// match this Cilium userspace instance. If not, it must be removed
	ctmap.DeleteIfUpgradeNeeded()

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
		if err := r.endpointManager.RestoreEndpoint(ep); err != nil {
			r.logger.Warn("Unable to restore endpoint", logfields.Error, err)
			// remove endpoint from slice of endpoints to restore
			state.restored = slices.Delete(state.restored, i, i+1)
		}
	}

	endpointsToRegenerate := make([]*endpoint.Endpoint, 0, len(state.restored))
	for _, ep := range state.restored {
		if ep.IsHost() && r.ipSecAgent.Enabled() {
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
			r.logger.Info("Successfully restored Host endpoint. Scheduling regeneration", logfields.EndpointID, ep.ID)
			if err := ep.RegenerateAfterRestore(r.endpointRegenerator, r.endpointMetadata.FetchK8sMetadataForEndpoint); err != nil {
				r.logger.Debug(
					"Error regenerating Host endpoint during restore",
					logfields.Error, err,
					logfields.EndpointID, ep.ID,
				)
			}
			continue
		}

		endpointsToRegenerate = append(endpointsToRegenerate, ep)
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
			r.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{
				NoIdentityRelease: true,
				NoIPRelease:       true,
			})
			endpointCleanupCompleted.Done()
		}(ep)
	}
	endpointCleanupCompleted.Wait()

	// Trigger regeneration for relevant restored endopints in a separate goroutine.
	go r.handleRestoredEndpointsRegeneration(endpointsToRegenerate)

	go func() {
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
	startTime := time.Now()
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

	total, regenerated, failed := 0, 0, 0
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

func (r *endpointRestorer) InitRestore() {
	if !option.Config.RestoreState {
		r.logger.Info("State restore is disabled. Existing endpoints on node are ignored")
		return
	}

	bootstrapStats.restore.Start()
	defer bootstrapStats.restore.End(true)

	// When we regenerate restored endpoints, it is guaranteed that we have
	// received the full list of policies present at the time the daemon
	// is bootstrapped.
	r.regenerateRestoredEndpoints(r.restoreState)

	close(r.endpointRestoreComplete)
}
