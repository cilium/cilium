// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/lthibault/jitterbug/v2"
	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/manager/tables"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	CRDStatusUpdateInterval = 5 * time.Second
	MaxConditionsMessageLen = 32 * 1024
)

type StatusReconciler struct {
	lock.Mutex

	Logger              logrus.FieldLogger
	ClientSet           k8s_client.Clientset
	LocalNodeResource   daemon_k8s.LocalCiliumNodeResource
	DB                  *statedb.DB
	ReconcileErrorTable statedb.RWTable[*tables.BGPReconcileError]
	nodeName            string
	bgpNodeConfig       store.BGPCPResourceStore[*v2.CiliumBGPNodeConfig]
	desiredStatus       *v2.CiliumBGPNodeStatus
	runningStatus       *v2.CiliumBGPNodeStatus
	reconcileInterval   time.Duration
	conditionsUpdated   bool
}

type StatusReconcilerIn struct {
	cell.In

	DB                  *statedb.DB
	ReconcileErrorTable statedb.RWTable[*tables.BGPReconcileError]
	DaemonConfig        *option.DaemonConfig
	Job                 job.Group
	ClientSet           k8s_client.Clientset
	Logger              logrus.FieldLogger
	LocalNode           daemon_k8s.LocalCiliumNodeResource
	BGPNodeConfig       store.BGPCPResourceStore[*v2.CiliumBGPNodeConfig]
}

type StatusReconcilerOut struct {
	cell.Out

	Reconciler StateReconciler `group:"bgp-state-reconciler-v2"`
}

func NewStatusReconciler(in StatusReconcilerIn) StatusReconcilerOut {
	if !in.DaemonConfig.BGPControlPlaneEnabled() {
		return StatusReconcilerOut{}
	}
	// CRD Status reconciler is disabled if there is no kubernetes support
	if !in.ClientSet.IsEnabled() {
		return StatusReconcilerOut{}
	}

	r := &StatusReconciler{
		Logger:              in.Logger.WithField(types.ReconcilerLogField, "CRD_Status"),
		LocalNodeResource:   in.LocalNode,
		ClientSet:           in.ClientSet,
		DB:                  in.DB,
		ReconcileErrorTable: in.ReconcileErrorTable,
		bgpNodeConfig:       in.BGPNodeConfig,
		reconcileInterval:   CRDStatusUpdateInterval,
		desiredStatus:       &v2.CiliumBGPNodeStatus{},
		runningStatus:       &v2.CiliumBGPNodeStatus{},
	}

	// If the status reporting is disabled, schedule a job to cleanup
	// status field. Otherwise, users may see the stale status that
	// previously reported.
	if !in.DaemonConfig.EnableBGPControlPlaneStatusReport {
		in.Job.Add(job.OneShot(
			"bgp-crd-status-cleanup",
			r.cleanupStatus,
		))
		return StatusReconcilerOut{}
	}

	in.Job.Add(job.OneShot("bgp-crd-status-initialize", func(ctx context.Context, health cell.Health) error {
		r.Logger.Debug("Initializing")

		for event := range r.LocalNodeResource.Events(ctx) {
			switch event.Kind {
			case resource.Upsert:
				r.Lock()
				r.nodeName = event.Object.GetName()
				r.Unlock()
			}
			event.Done(nil)
		}
		return nil
	}))

	in.Job.Add(job.OneShot("bgp-crd-status-update-job", func(ctx context.Context, health cell.Health) (err error) {
		r.Logger.Debug("Update job running")

		// Ticker with jitter is used to avoid all nodes updating API server at the same time.
		// BGP updates will simultaneously on all nodes ( on external or internal changes),
		// which will result in status update.
		// We want to stagger the status updates to avoid thundering herd problem.
		ticker := jitterbug.New(
			r.reconcileInterval,
			&jitterbug.Norm{Stdev: time.Millisecond * 500},
		)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Reconciliation of CRD status is done every CRDStatusUpdateInterval seconds, if there is an error it will be retried
				// with exponential backoff. Exponential backoff is capped at 10 retries, after which we will again fall back to
				// starting interval of CRDStatusUpdateInterval.
				// This will result in see-saw pattern of retries, which provides some level of backoff mechanism.
				// Error will be logged once 10 retries fails consecutively, so we do not flood the logs with errors on each retry.
				err := r.reconcileWithRetry(ctx)
				if err != nil {
					r.Logger.WithError(err).Error("Failed to update CiliumBGPNodeConfig status after retries")
				}

			case <-ctx.Done():
				r.Logger.Debug("CRD status update job stopped")
				return nil
			}
		}
	}))

	in.Job.Add(job.OneShot("bgp-reconcile-error-statedb-tracker", func(ctx context.Context, health cell.Health) error {
		r.Logger.Debug("StateDB reconcile-error tracker running")
		observable := statedb.Observable[*tables.BGPReconcileError](in.DB, in.ReconcileErrorTable)
		ch := stream.ToChannel[statedb.Change[*tables.BGPReconcileError]](ctx, observable)

		for range ch {
			if err := r.updateErrorConditions(); err != nil {
				r.Logger.WithError(err).Error("Failed to update error conditions")
			}
		}
		return nil
	}))

	return StatusReconcilerOut{
		Reconciler: r,
	}
}

func (r *StatusReconciler) updateErrorConditions() error {
	r.Lock()
	defer r.Unlock()

	// Node name is not set yet
	if r.nodeName == "" {
		return nil
	}

	bgpNodeConfig, exists, err := r.bgpNodeConfig.GetByKey(resource.Key{Name: r.nodeName})
	if err != nil {
		return err
	}

	if !exists {
		// BGPNodeConfig object not found, there is nowhere to update the status.
		return nil
	}

	var instanceErrors []tables.BGPReconcileError
	iter := r.ReconcileErrorTable.All(r.DB.ReadTxn())
	for errObj := range iter {
		instanceErrors = append(instanceErrors, *errObj)
	}

	// sort instance errors by instance name and then by error ID
	sort.Slice(instanceErrors, func(i, j int) bool {
		if strings.Compare(instanceErrors[i].Instance, instanceErrors[j].Instance) == 0 {
			return instanceErrors[i].ErrorID < instanceErrors[j].ErrorID
		}
		return strings.Compare(instanceErrors[i].Instance, instanceErrors[j].Instance) < 0
	})

	// combine all errors into a single message
	var message strings.Builder
	for _, errObj := range instanceErrors {
		// maximum length of message can be 32*1024
		if message.Len()+len(errObj.String()) >= MaxConditionsMessageLen {
			break
		}
		message.WriteString(fmt.Sprintf("%s: %s\n", errObj.Instance, errObj.Error))
	}

	cond := metav1.Condition{
		Type:               v2.BGPInstanceConditionReconcileError,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: bgpNodeConfig.GetGeneration(),
		Reason:             "BGPReconcileError",
	}

	if len(instanceErrors) > 0 {
		cond.Status = metav1.ConditionTrue
		cond.Message = message.String()
	}

	if updated := meta.SetStatusCondition(&r.desiredStatus.Conditions, cond); updated {
		r.conditionsUpdated = true
	}
	return nil
}

func (r *StatusReconciler) Name() string {
	return CRDStatusReconcilerName
}

func (r *StatusReconciler) Priority() int {
	return CRDStatusReconcilerPriority
}

func (r *StatusReconciler) Reconcile(ctx context.Context, params StateReconcileParams) error {
	r.Lock()
	defer r.Unlock()

	// do not reconcile if not in BGPv2 mode
	if params.ConfigMode.Get() != mode.BGPv2 {
		// reset status to empty if not in BGPv2 mode
		r.desiredStatus = &v2.CiliumBGPNodeStatus{}
		return nil
	}

	current := r.desiredStatus.DeepCopy()

	if params.UpdatedInstance != nil {
		r.Logger.WithFields(logrus.Fields{
			types.InstanceLogField: params.UpdatedInstance.Config.Name,
		}).Debug("Reconciling CRD status")

		// get updated status for the instance
		instanceStatus, err := r.getInstanceStatus(ctx, params.UpdatedInstance)
		if err != nil {
			return err
		}

		found := false
		for idx, instance := range current.BGPInstances {
			if instance.Name == instanceStatus.Name {
				current.BGPInstances[idx] = *instanceStatus
				found = true
				break
			}
		}
		if !found {
			current.BGPInstances = append(current.BGPInstances, *instanceStatus)
		}
	}

	if params.DeletedInstance != "" {
		r.Logger.WithFields(logrus.Fields{
			types.InstanceLogField: params.DeletedInstance,
		}).Debug("Deleting instance from CRD status")

		// remove instance from status
		for idx, instance := range current.BGPInstances {
			if instance.Name == params.DeletedInstance {
				current.BGPInstances = append(current.BGPInstances[:idx], current.BGPInstances[idx+1:]...)
				break
			}
		}
	}

	r.desiredStatus = current
	return nil
}

func (r *StatusReconciler) cleanupStatus(ctx context.Context, health cell.Health) error {
	var nodeName string

	// Wait for the local node name
	for event := range r.LocalNodeResource.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			nodeName = event.Key.Name
		}

		event.Done(nil)

		if nodeName != "" {
			break
		}
	}

	return resiliency.Retry(ctx, 3*time.Second, 20, func(ctx context.Context, _ int) (bool, error) {
		// Patch with an empty status
		emptyStatus := []k8s.JSONPatch{
			{
				OP:    "replace",
				Path:  "/status",
				Value: &v2.CiliumBGPNodeStatus{},
			},
		}

		patch, err := json.Marshal(emptyStatus)
		if err != nil {
			return false, fmt.Errorf("BUG: cannot marshal empty status: %w", err)
		}

		if _, err := r.ClientSet.CiliumV2().CiliumBGPNodeConfigs().Patch(
			ctx,
			nodeName,
			k8s_types.JSONPatchType,
			patch,
			metav1.PatchOptions{FieldManager: r.Name()},
			"status",
		); err != nil {
			// NodeConfig for this node doesn't exist yet. Then,
			// there's no status to cleanup.
			if k8sErrors.IsNotFound(err) {
				return true, nil
			}
			return false, nil
		}

		return true, nil
	})
}

func (r *StatusReconciler) getInstanceStatus(ctx context.Context, instance *instance.BGPInstance) (*v2.CiliumBGPNodeInstanceStatus, error) {
	res := &v2.CiliumBGPNodeInstanceStatus{
		Name:     instance.Config.Name,
		LocalASN: instance.Config.LocalASN,
	}

	// get peer status
	peers, err := instance.Router.GetPeerState(ctx)
	if err != nil {
		return nil, err
	}

	for _, configuredPeers := range instance.Config.Peers {
		if configuredPeers.PeerASN == nil || configuredPeers.PeerAddress == nil {
			continue
		}

		peerStatus := v2.CiliumBGPNodePeerStatus{
			Name:        configuredPeers.Name,
			PeerAddress: *configuredPeers.PeerAddress,
			PeerASN:     configuredPeers.PeerASN,
		}

		for _, runningPeerState := range peers.Peers {
			if runningPeerState.PeerAddress != *configuredPeers.PeerAddress {
				continue
			}

			if *configuredPeers.PeerASN == 0 { // If PeerASN is not set, use the ASN from the running state
				peerStatus.PeerASN = ptr.To[int64](runningPeerState.PeerAsn)
			}

			peerStatus.PeeringState = ptr.To[string](runningPeerState.SessionState)

			// Update established timestamp
			if runningPeerState.SessionState == types.SessionEstablished.String() {
				// Time API only allows add with duration, to go back in time from uptime timestamp we need to subtract
				// uptime from current time.
				establishedTime := time.Now().Add(-time.Duration(runningPeerState.UptimeNanoseconds))
				peerStatus.EstablishedTime = ptr.To[string](establishedTime.Format(time.RFC3339))
			}

			// applied timers
			peerStatus.Timers = &v2.CiliumBGPTimersState{
				AppliedHoldTimeSeconds:  ptr.To[int32](int32(runningPeerState.AppliedHoldTimeSeconds)),
				AppliedKeepaliveSeconds: ptr.To[int32](int32(runningPeerState.AppliedKeepAliveTimeSeconds)),
			}

			// update route counts
			for _, af := range runningPeerState.Families {
				peerStatus.RouteCount = append(peerStatus.RouteCount, v2.BGPFamilyRouteCount{
					Afi:        af.Afi,
					Safi:       af.Safi,
					Advertised: ptr.To[int32](int32(af.Advertised)),
					Received:   ptr.To[int32](int32(af.Received)),
				})
			}

			// peer status updated, no need to iterate further
			break
		}

		res.PeerStatuses = append(res.PeerStatuses, peerStatus)
	}

	return res, nil
}

func (r *StatusReconciler) reconcileWithRetry(ctx context.Context) error {
	bo := wait.Backoff{
		Duration: r.reconcileInterval,
		Factor:   1.2,
		Jitter:   0.5,
		Steps:    10,
	}

	retryFn := func(ctx context.Context) (bool, error) {
		err := r.reconcileCRDStatus(ctx)
		if err != nil {
			r.Logger.WithError(err).Debug("Failed to update CiliumBGPNodeConfig status")
			return false, nil
		}
		return true, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

func (r *StatusReconciler) reconcileCRDStatus(ctx context.Context) error {
	r.Lock()
	defer r.Unlock()

	// Node name is not set yet, on subsequent retries status field will get updated.
	if r.nodeName == "" {
		return nil
	}

	if r.desiredStatus.DeepEqual(r.runningStatus) && !r.conditionsUpdated {
		return nil
	}

	statusCpy := r.desiredStatus.DeepCopy()

	replaceStatus := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: statusCpy,
		},
	}

	createStatusPatch, err := json.Marshal(replaceStatus)
	if err != nil {
		return fmt.Errorf("json.Marshal(%v) failed: %w", replaceStatus, err)
	}

	client := r.ClientSet.CiliumV2().CiliumBGPNodeConfigs()
	_, err = client.Patch(ctx, r.nodeName,
		k8s_types.JSONPatchType, createStatusPatch, metav1.PatchOptions{
			FieldManager: r.Name(),
		}, "status")
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			// it is possible that CiliumBGPNodeConfig is deleted, in that case we set running config to
			// empty and return. Desired config will eventually be set to empty by state reconciler.
			r.runningStatus = &v2.CiliumBGPNodeStatus{}
			return nil
		}

		return fmt.Errorf("failed to update CRD status: %w", err)
	}

	r.runningStatus = statusCpy
	r.conditionsUpdated = false // reset conditions updated flag
	r.Logger.WithField(types.BGPNodeConfigLogField, r.nodeName).Debug("Updated resource status")
	return nil
}
