// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2announcer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

var Cell = cell.Module("l2-announcer", "L2 Announcer",
	cell.Provide(NewL2Announcer),
)

type l2AnnouncerParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Logger    logrus.FieldLogger

	DaemonConfig         *option.DaemonConfig
	Clientset            k8sClient.Clientset
	Services             resource.Resource[*slim_corev1.Service]
	L2AnnouncementPolicy resource.Resource[*cilium_api_v2alpha1.CiliumL2AnnouncementPolicy]
	LocalNodeResource    *k8s.LocalCiliumNodeResource
	L2AnnounceTable      statedb.Table[*tables.L2AnnounceEntry]
	StateDB              statedb.DB
	JobRegistry          job.Registry
}

// L2Announcer takes all L2 announcement policies and filters down to those that match the labels of the local node. It
// then searches all services that match the selectors of the policies. For each service, we attempt to take a lease,
// the holder node persists all IPs and netdev combinations selected by the policy to the L2AnnounceTable. Datapath
// components consume them and handle traffic for the IP+netdev entries.
type L2Announcer struct {
	Params l2AnnouncerParams

	svcStore    resource.Store[*slim_corev1.Service]
	policyStore resource.Store[*cilium_api_v2alpha1.CiliumL2AnnouncementPolicy]
	localNode   *v2.CiliumNode

	jobgroup job.Group

	leaderChannel chan leaderElectionEvent
	devicesChan   chan []string

	// selectedPolicies matching the current node.
	selectedPolicies map[resource.Key]*selectedPolicy
	// Services which are selected by one or more policies for which we thus want to participate in leader election.
	// Indexed by service key.
	selectedServices map[resource.Key]*selectedService
	// A list of devices which can be matched by the policies
	devices []string
}

func NewL2Announcer(params l2AnnouncerParams) *L2Announcer {
	// These values were picked because it seemed right, change if necessary
	const leaderElectionBufferSize = 16
	const devicesBufferSize = 16
	announcer := &L2Announcer{
		Params: params,
		jobgroup: params.JobRegistry.NewGroup(
			job.WithLogger(params.Logger),
			job.WithPprofLabels(pprof.Labels("cell", "l2-announcer")),
		),
		selectedServices: make(map[resource.Key]*selectedService),
		selectedPolicies: make(map[resource.Key]*selectedPolicy),
		leaderChannel:    make(chan leaderElectionEvent, leaderElectionBufferSize),
		devicesChan:      make(chan []string, devicesBufferSize),
	}

	params.Lifecycle.Append(announcer.jobgroup)

	if !params.DaemonConfig.EnableL2Announcements {
		// If the L2 announcement feature is disabled, garbage collect any leases from previous runs when the feature
		// might have been active. Just once, not on a timer.
		announcer.jobgroup.Add(job.OneShot("l2-announcer lease-gc", announcer.leaseGC))
		return announcer
	}

	announcer.jobgroup.Add(job.OneShot("l2-announcer run", announcer.run))
	announcer.jobgroup.Add(job.Timer("l2-announcer lease-gc", announcer.leaseGC, time.Minute))

	return announcer
}

// DevicesChanged can be invoked by an external component responsible for discovering all available network devices to
// inform this component of all the devices we can use for L2 announcements.
func (l2a *L2Announcer) DevicesChanged(devices []string) {
	select {
	// Send the change to the central routine to avoid race conditions
	case l2a.devicesChan <- devices:
	default:
	}
}

func (l2a *L2Announcer) run(ctx context.Context) error {
	var err error
	l2a.svcStore, err = l2a.Params.Services.Store(ctx)
	if err != nil {
		return fmt.Errorf("get service store: %w", err)
	}

	l2a.policyStore, err = l2a.Params.L2AnnouncementPolicy.Store(ctx)
	if err != nil {
		return fmt.Errorf("get policy store: %w", err)
	}

	svcChan := l2a.Params.Services.Events(ctx)
	policyChan := l2a.Params.L2AnnouncementPolicy.Events(ctx)
	localNodeChan := l2a.Params.LocalNodeResource.Events(ctx)

	// We have to first have a local node before we can start processing other events.
	for {
		select {
		case event := <-localNodeChan:
			if err := l2a.processLocalNodeEvent(ctx, event); err != nil {
				l2a.Params.Logger.WithError(err).Error("Error processing local node event")
			}
		}

		if l2a.localNode != nil {
			break
		}
	}

	for {
		select {
		case <-ctx.Done():
		case event := <-svcChan:
			if err := l2a.processSvcEvent(event); err != nil {
				l2a.Params.Logger.WithError(err).Error("Error processing service event")
			}
		case event := <-policyChan:
			if err := l2a.processPolicyEvent(ctx, event); err != nil {
				l2a.Params.Logger.WithError(err).Error("Error processing policy event")
			}

		case event := <-localNodeChan:
			if err := l2a.processLocalNodeEvent(ctx, event); err != nil {
				l2a.Params.Logger.WithError(err).Error("Error processing local node event")
			}

		case event := <-l2a.leaderChannel:
			if err := l2a.processLeaderEvent(event); err != nil {
				l2a.Params.Logger.WithError(err).Error("Error processing leader event")
			}

		case devices := <-l2a.devicesChan:
			if err := l2a.processDevicesChanged(ctx, devices); err != nil {
				l2a.Params.Logger.WithError(err).Error("Error processing devices changed event")
			}
		}
	}
}

// Called periodically to garbage collect any leases which are no longer held by any agent.
// This is needed since agents do not track leases for services that we no longer select.
func (l2a *L2Announcer) leaseGC(ctx context.Context) error {
	leaseClient := l2a.Params.Clientset.CoordinationV1().Leases(l2a.leaseNamespace())
	list, err := leaseClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("leaseClient.List: %w", err)
	}

	for _, lease := range list.Items {
		if !strings.HasPrefix(lease.Name, leasePrefix) {
			continue
		}

		if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" {
			continue
		}

		err = leaseClient.Delete(ctx, lease.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("leaseClient.Delete(%s): %w", lease.Name, err)
		}
	}

	return nil
}

func (l2a *L2Announcer) processDevicesChanged(ctx context.Context, devices []string) error {
	l2a.devices = devices

	var errs error

	// Upsert every known policy which will re-evaluate device matching
	for _, selectedPolicy := range l2a.selectedPolicies {
		if err := l2a.upsertPolicy(ctx, selectedPolicy.policy); err != nil {
			errs = errors.Join(errs, fmt.Errorf("upsert policy: %w", err))
		}
	}

	return errs
}

func (l2a *L2Announcer) processPolicyEvent(ctx context.Context, event resource.Event[*cilium_api_v2alpha1.CiliumL2AnnouncementPolicy]) error {
	var err error
	switch event.Kind {
	case resource.Upsert:
		err = l2a.upsertPolicy(ctx, event.Object)
		if err != nil {
			err = fmt.Errorf("upsert policy: %w", err)
		}

	case resource.Delete:
		err = l2a.delPolicy(event.Key)
		if err != nil {
			err = fmt.Errorf("delete policy: %w", err)
		}

	case resource.Sync:
	}

	// if `err` is not nil, the event will be retried by the resource.
	event.Done(err)
	return err
}

func (l2a *L2Announcer) upsertSvc(svc *slim_corev1.Service) error {
	key := serviceKey(svc)
	ss, found := l2a.selectedServices[key]
	if found {
		// Update service object, labels or IPs may have changed
		ss.svc = svc

		// Since labels may have changed, remove all matching policies, re-match against all known policies.
		ss.byPolicies = nil
		for policyKey, selectedPolicy := range l2a.selectedPolicies {
			if selectedPolicy.serviceSelector.Matches(labels.Set(svc.Labels)) {
				ss.byPolicies = append(ss.byPolicies, policyKey)
			}
		}

		// If no policies match anymore, delete the service
		if len(ss.byPolicies) == 0 {
			// gcOrphanedService deletes when a service has no policies, which is the case here.
			// It also stops any lease subscription and reconciles the output table.
			l2a.gcOrphanedService(ss)
			return nil
		}

		// Since IPs may have changed, re-calculate its entries in the output table, if we are leader
		err := l2a.recalculateL2EntriesTableEntries(ss)
		if err != nil {
			return fmt.Errorf("recalculateL2EntriesTableEntries: %w", err)
		}

		return nil
	}

	// Service is not selected, check if any policies match.
	var matchingPolicies []resource.Key
	for policyKey, selectedPolicy := range l2a.selectedPolicies {
		if selectedPolicy.serviceSelector.Matches(labels.Set(svc.Labels)) {
			matchingPolicies = append(matchingPolicies, policyKey)
		}
	}

	// Add the services to list of selected services if at least 1 policy matches it.
	if len(matchingPolicies) >= 1 {
		l2a.addSelectedService(svc, matchingPolicies)
	}

	return nil
}

func (l2a *L2Announcer) delSvc(key resource.Key) error {
	ss, found := l2a.selectedServices[key]
	if !found {
		return nil
	}

	// gcOrphanedService will delete the service if it has no policies that match, so remove the policy references
	// and call gcOrphanedService. It will remove the service, stop leader election for it and reconcile the output
	// table if we were leader for the service.
	ss.byPolicies = nil
	err := l2a.gcOrphanedService(ss)
	if err != nil {
		return fmt.Errorf("gcOrphanedService: %w", err)
	}

	return nil
}

func (l2a *L2Announcer) processSvcEvent(event resource.Event[*slim_corev1.Service]) error {
	var err error
	switch event.Kind {
	case resource.Upsert:
		err = l2a.upsertSvc(event.Object)
		if err != nil {
			err = fmt.Errorf("upsert service: %w", err)
		}

	case resource.Delete:
		err = l2a.delSvc(event.Key)
		if err != nil {
			err = fmt.Errorf("delete service: %w", err)
		}

	case resource.Sync:
	}

	// if `err` is not nil, this will cause the resource to retry the event.
	event.Done(err)
	return err
}

func policyKey(policy *cilium_api_v2alpha1.CiliumL2AnnouncementPolicy) resource.Key {
	return resource.Key{Name: policy.Name}
}

func serviceKey(svc *slim_corev1.Service) resource.Key {
	return resource.Key{Namespace: svc.Namespace, Name: svc.Name}
}

func (l2a *L2Announcer) upsertPolicy(ctx context.Context, policy *cilium_api_v2alpha1.CiliumL2AnnouncementPolicy) error {
	key := policyKey(policy)

	// Remove all references to the old policy, since the new version might not match the service anymore.
	for _, ss := range l2a.selectedServices {
		idx := slices.Index(ss.byPolicies, key)
		if idx != -1 {
			ss.byPolicies = slices.Delete(ss.byPolicies, idx, idx+1)
		}
	}

	if policy.Spec.NodeSelector != nil {
		nodeselector, err := slim_meta_v1.LabelSelectorAsSelector(policy.Spec.NodeSelector)
		if err != nil {
			l2a.updatePolicyStatus(ctx, policy, "bad-node-selector", err)
			return fmt.Errorf("make node selector: %w", err)
		}

		// The new policy does not match the node selector
		if !nodeselector.Matches(labels.Set(l2a.localNode.Labels)) {
			err = l2a.delPolicy(key)
			if err != nil {
				return fmt.Errorf("del policy: %w", err)
			}
			return nil
		}
	}

	// If no interface regexes are given, all devices match. Otherwise only devices matching the policy
	// will be selected.
	var selectedDevices []string
	if len(policy.Spec.Interfaces) == 0 {
		selectedDevices = l2a.devices
	} else {
		for _, strRegex := range policy.Spec.Interfaces {
			regex, err := regexp.Compile(strRegex)
			if err != nil {
				// TODO annotate policy status
				return fmt.Errorf("policy compile interface regex: %w", err)
			}

			for _, device := range l2a.devices {
				if slices.Contains(selectedDevices, device) {
					continue
				}

				if regex.MatchString(device) {
					selectedDevices = append(selectedDevices, device)
				}
			}
		}
	}

	// If no selector is specified, all services match.
	serviceSelector := labels.Everything()
	if policy.Spec.ServiceSelector != nil {
		var err error
		serviceSelector, err = slim_meta_v1.LabelSelectorAsSelector(policy.Spec.ServiceSelector)
		if err != nil {
			// TODO annotate policy status
			return fmt.Errorf("make service selector: %w", err)
		}
	}

	l2a.selectedPolicies[key] = &selectedPolicy{
		policy:          policy,
		serviceSelector: serviceSelector,
		selectedDevices: selectedDevices,
	}

	// Check all services, if they match the policy, mark the selected service as matching this policy.
	// Or add to the selected services if it was not there already.
	for _, svc := range l2a.svcStore.List() {
		if !serviceSelector.Matches(labels.Set(svc.Labels)) {
			continue
		}

		ss, found := l2a.selectedServices[serviceKey(svc)]
		if found {
			if slices.Index(ss.byPolicies, key) == -1 {
				ss.byPolicies = append(ss.byPolicies, key)
			}

			// recalculate in case the policy update causes neighbor proxy entries to be generated differently
			if err := l2a.recalculateL2EntriesTableEntries(ss); err != nil {
				return fmt.Errorf("recalculateNeighborProxyTableEntries: %w", err)
			}

			continue
		}

		l2a.addSelectedService(svc, []resource.Key{key})
	}

	err := l2a.gcOrphanedServices()
	if err != nil {
		return fmt.Errorf("gcOrphanedServices: %w", err)
	}

	return nil
}

// updatePolicyStatus updates the policy status annotation of the given type, it is called every time an aspect of the
// policy has been checked. If `err` is nil, and no conditions exist, no action is taken. If `err` contains an actual
// error a condition is added or updated and if a condition exists and `err` == nil follows the condition is marked
// false
func (l2a *L2Announcer) updatePolicyStatus(
	ctx context.Context,
	policy *cilium_api_v2alpha1.CiliumL2AnnouncementPolicy,
	typ string,
	err error,
) error {
	// Find an existing condition of the given type
	idx := slices.IndexFunc(policy.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == typ
	})

	var cond *metav1.Condition
	// If no condition of this type exists
	if idx < 0 {
		// If the update call was to clear an error, no action has to happen
		if err == nil {
			return nil
		}

		policy.Status.Conditions = append(policy.Status.Conditions, metav1.Condition{})
		idx = len(policy.Status.Conditions) - 1
	}
	cond = &policy.Status.Conditions[idx]

	cond.Type = typ
	cond.Status = metav1.ConditionTrue
	if err == nil {
		cond.Status = metav1.ConditionFalse
	}
	cond.LastTransitionTime = metav1.Now()
	cond.ObservedGeneration = policy.GetGeneration()
	if err == nil {
		cond.Message = ""
	} else {
		cond.Message = err.Error()
	}

	policyClient := l2a.Params.Clientset.CiliumV2alpha1().CiliumL2AnnouncementPolicies()
	_, err = policyClient.UpdateStatus(ctx, policy, metav1.UpdateOptions{})
	return err
}

func (l2a *L2Announcer) delPolicy(key resource.Key) error {
	for _, ss := range l2a.selectedServices {
		idx := slices.Index(ss.byPolicies, key)
		if idx != -1 {
			ss.byPolicies = slices.Delete(ss.byPolicies, idx, idx+1)
		}
	}

	delete(l2a.selectedPolicies, key)

	err := l2a.gcOrphanedServices()
	if err != nil {
		return fmt.Errorf("gcOrphanedServices: %w", err)
	}

	return nil
}

// The leaderelection library enforces sane timer values, this function verifiers that the user input follows the rules
// and overwrites to sane defaults if they don't.
func (l2a *L2Announcer) leaseTimings() (leaseDuration, renewDeadline, retryPeriod time.Duration) {
	leaseDuration = l2a.Params.DaemonConfig.L2AnnouncerLeaseDuration
	renewDeadline = l2a.Params.DaemonConfig.L2AnnouncerRenewDeadline
	retryPeriod = l2a.Params.DaemonConfig.L2AnnouncerRetryPeriod

	log := l2a.Params.Logger

	if leaseDuration < 1 {
		log.WithFields(logrus.Fields{
			"leaseDuration": leaseDuration,
		}).Warnf(
			"--%s must be greater than 1ns, defaulting to 3s",
			option.L2AnnouncerLeaseDuration,
		)
		leaseDuration = 3 * time.Second
	}

	if renewDeadline < 1 {
		log.WithFields(logrus.Fields{
			"renewDeadline": renewDeadline,
		}).Warnf(
			"--%s must be greater than 1ns, defaulting to 1s",
			option.L2AnnouncerRenewDeadline,
		)
		renewDeadline = time.Second
	}

	if retryPeriod < 1 {
		log.WithFields(logrus.Fields{
			"retryPeriod": retryPeriod,
		}).Warnf(
			"--%s must be greater than 1ns, defaulting to 200ms",
			option.L2AnnouncerRetryPeriod,
		)
		retryPeriod = 200 * time.Millisecond
	}

	if renewDeadline <= time.Duration(leaderelection.JitterFactor*float64(retryPeriod)) {
		log.WithFields(logrus.Fields{
			"renewDeadline": renewDeadline,
			"retryPeriod":   retryPeriod,
		}).Warnf(
			"--%s must be greater than --%s * %.2f, defaulting to --%s * 2",
			option.L2AnnouncerRenewDeadline,
			option.L2AnnouncerRetryPeriod,
			leaderelection.JitterFactor,
			option.L2AnnouncerRetryPeriod,
		)
		renewDeadline = 2 * retryPeriod
	}

	if leaseDuration <= renewDeadline {
		log.WithFields(logrus.Fields{
			"leaseDuration": leaseDuration,
			"renewDeadline": renewDeadline,
		}).Warnf(
			"--%s must be greater than --%s, defaulting to a 2/1 ratio",
			option.L2AnnouncerLeaseDuration,
			option.L2AnnouncerRenewDeadline,
		)
		leaseDuration = 2 * renewDeadline
	}

	return leaseDuration, renewDeadline, retryPeriod
}

func (l2a *L2Announcer) addSelectedService(svc *slim_corev1.Service, byPolicies []resource.Key) {
	leaseDuration, renewDeadline, retryPeriod := l2a.leaseTimings()
	ss := &selectedService{
		svc:           svc,
		byPolicies:    byPolicies,
		lock:          l2a.newLeaseLock(svc),
		done:          make(chan struct{}),
		leaderChannel: l2a.leaderChannel,
		leaseDuration: leaseDuration,
		renewDeadline: renewDeadline,
		retryPeriod:   retryPeriod,
	}

	l2a.selectedServices[serviceKey(svc)] = ss

	// kick off leader election job
	l2a.jobgroup.Add(job.OneShot(
		fmt.Sprintf("leader-election/%s/%s", svc.Namespace, svc.Name),
		ss.serviceLeaderElection),
	)
}

func (l2a *L2Announcer) leaseNamespace() string {
	ns := l2a.Params.DaemonConfig.K8sNamespace
	// If due to any reason the CILIUM_K8S_NAMESPACE is not set we assume the operator
	// to be in default namespace.
	if ns == "" {
		ns = metav1.NamespaceDefault
	}

	return ns
}

const leasePrefix = "cilium-l2announce"

func (l2a *L2Announcer) newLeaseLock(svc *slim_corev1.Service) *resourcelock.LeaseLock {
	return &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Namespace: l2a.leaseNamespace(),
			Name:      fmt.Sprintf("%s-%s-%s", leasePrefix, svc.Namespace, svc.Name),
		},
		Client: l2a.Params.Clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: l2a.localNode.Name,
		},
	}
}

// Check all selected services, delete services which are no longer selected by any of the policies.
func (l2a *L2Announcer) gcOrphanedServices() error {
	for _, ss := range l2a.selectedServices {
		err := l2a.gcOrphanedService(ss)
		if err != nil {
			return fmt.Errorf("gcOrphanedService: %w", err)
		}
	}

	return nil
}

func (l2a *L2Announcer) gcOrphanedService(ss *selectedService) error {
	// Only GC policies that have been orphaned (all policies that created it has gone away)
	if len(ss.byPolicies) > 0 {
		return nil
	}

	// Stop leader election routine
	ss.stop()

	// Recalculation will remove all entries since we stopped the leader election.
	if err := l2a.recalculateL2EntriesTableEntries(ss); err != nil {
		return fmt.Errorf("recalculateNeighborProxyTableEntries: %w", err)
	}

	// Remove service from selected services
	delete(l2a.selectedServices, serviceKey(ss.svc))
	return nil
}

func (l2a *L2Announcer) processLocalNodeEvent(ctx context.Context, event resource.Event[*v2.CiliumNode]) error {
	var err error
	if event.Kind == resource.Upsert {
		err = l2a.upsertLocalNode(ctx, event.Object)
		if err != nil {
			err = fmt.Errorf("upsert local node: %w", err)
		}
	}

	event.Done(err)
	return err
}

func (l2a *L2Announcer) upsertLocalNode(ctx context.Context, localNode *v2.CiliumNode) error {
	// If the label set did not change, nothing to do.
	if l2a.localNode != nil && labels.Equals(l2a.localNode.Labels, labels.Set(localNode.Labels)) {
		return nil
	}

	l2a.localNode = localNode

	// Delete any policies that no longer match the new label set
	var errs error
	for key, selectedPolicy := range l2a.selectedPolicies {
		if selectedPolicy.serviceSelector.Matches(labels.Set(l2a.localNode.Labels)) {
			continue
		}

		err := l2a.delPolicy(key)
		if err != nil {
			errors.Join(errs, fmt.Errorf("make node selector: %w", err))
			continue
		}
	}

	// Upsert all policies, the upsert function checks if they match the new label set
	for _, policy := range l2a.policyStore.List() {
		err := l2a.upsertPolicy(ctx, policy)
		if err != nil {
			errors.Join(errs, fmt.Errorf("make node selector: %w", err))
			continue
		}
	}

	return errs
}

func (l2a *L2Announcer) processLeaderEvent(event leaderElectionEvent) error {
	event.selectedService.currentlyLeader = event.typ == leaderElectionLeading
	err := l2a.recalculateL2EntriesTableEntries(event.selectedService)
	if err != nil {
		return fmt.Errorf("recalculateNeighborProxyTableEntries: %w", err)
	}

	return nil
}

func (l2a *L2Announcer) recalculateL2EntriesTableEntries(ss *selectedService) error {
	txn := l2a.Params.StateDB.WriteTxn()
	w := l2a.Params.L2AnnounceTable.Writer(txn)

	rev := txn.Revision()
	svcKey := serviceKey(ss.svc)

	entriesIter, err := w.Get(tables.ByProxyOrigin(svcKey))
	if err != nil {
		txn.Abort()
		return fmt.Errorf("get all entries with origin '%s': %w", svcKey, err)
	}

	// If we are not the leader, we should not have any proxy entries for the service.
	if !ss.currentlyLeader {
		// Remove origin from entries, and delete if no origins left
		err = statedb.ProcessEach(entriesIter, func(e *tables.L2AnnounceEntry) error {
			// Copy, since modifying objects directly is not allowed.
			e = e.DeepCopy()

			idx := slices.Index(e.Origins, svcKey)
			if idx != -1 {
				e.Origins = slices.Delete(e.Origins, idx, idx+1)
			}

			// Perform a soft delete
			if len(e.Origins) == 0 {
				e.Deleted = true
			}

			e.Revision = rev

			err := w.Insert(e)
			if err != nil {
				return fmt.Errorf("update in table: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("ProcessEach: %w", err)
		}

		err = txn.Commit()
		if err != nil {
			return fmt.Errorf("commit delete entries: %w", err)
		}

		return nil
	}

	desiredEntries := l2a.desiredEntries(ss)
	satisfiedEntries := make(map[string]bool)
	for key := range desiredEntries {
		satisfiedEntries[key] = false
	}

	// Loop over existing entries, delete undesired entries
	err = statedb.ProcessEach(entriesIter, func(e *tables.L2AnnounceEntry) error {
		key := fmt.Sprintf("%s/%s", e.IP, e.NetworkInterface)

		_, desired := desiredEntries[key]
		if desired {
			// Iterator only contains entries which already have the origin of the current svc.
			// So no need to add it in the second step.
			satisfiedEntries[key] = true
			return err
		}

		// Entry is undesired.

		// Copy, since modifying objects directly is not allowed.
		e = e.DeepCopy()

		idx := slices.Index(e.Origins, svcKey)
		if idx != -1 {
			e.Origins = slices.Delete(e.Origins, idx, idx+1)
		}

		if len(e.Origins) == 0 {
			// Perform a soft delete, if no services want this IP + NetDev anymore
			e.Deleted = true
		}

		e.Revision = rev

		err := w.Insert(e)
		if err != nil {
			return fmt.Errorf("update in table: %w", err)
		}
		return nil
	})
	if err != nil {
		txn.Abort()
		return fmt.Errorf("ProcessEach: %w", err)
	}

	// loop over the desired states, add any that are missing
	for key, satisfied := range satisfiedEntries {
		if satisfied {
			continue
		}

		entry := desiredEntries[key]
		existing, err := w.First(tables.ByProxyIPAndInterface(entry.IP, entry.NetworkInterface))
		if err != nil {
			txn.Abort()
			return fmt.Errorf("first: %w", err)
		}

		if existing == nil {
			existing = &tables.L2AnnounceEntry{
				IP:               entry.IP,
				NetworkInterface: entry.NetworkInterface,
			}
		}

		// Add our new origin to the existing origins, or if existing is nil (no entry existed), nothing will change.
		entry.Origins = append(existing.Origins, entry.Origins...)
		entry.Revision = rev

		// Insert or update
		err = w.Insert(entry)
		if err != nil {
			txn.Abort()
			return fmt.Errorf("insert new: %w", err)
		}
		continue
	}

	err = txn.Commit()
	if err != nil {
		return fmt.Errorf("commit delete entries: %w", err)
	}

	return nil
}

func (l2a *L2Announcer) desiredEntries(ss *selectedService) map[string]*tables.L2AnnounceEntry {
	entries := make(map[string]*tables.L2AnnounceEntry)

	for _, policyKey := range ss.byPolicies {
		selectedPolicy := l2a.selectedPolicies[policyKey]

		var IPs []net.IP
		if selectedPolicy.policy.Spec.LoadBalancerIPs {
			for _, ingress := range ss.svc.Status.LoadBalancer.Ingress {
				if ingress.IP == "" {
					continue
				}

				IPs = append(IPs, net.ParseIP(ingress.IP))
			}
		}

		if selectedPolicy.policy.Spec.ExternalIPs {
			for _, externalIP := range ss.svc.Spec.ExternalIPs {
				IPs = append(IPs, net.ParseIP(externalIP))
			}
		}

		for _, ip := range IPs {
			for _, iface := range selectedPolicy.selectedDevices {
				key := fmt.Sprintf("%s/%s", ip.String(), iface)
				entry, found := entries[key]
				if !found {
					entry = &tables.L2AnnounceEntry{
						IP:               ip,
						NetworkInterface: iface,
						Origins:          []resource.Key{serviceKey(ss.svc)},
					}
				}
				entries[key] = entry
			}
		}
	}

	return entries
}

type selectedService struct {
	// The last known version of the service
	svc *slim_corev1.Service
	// The policies which select this service.
	byPolicies []resource.Key

	// lease parameters
	leaseDuration time.Duration
	renewDeadline time.Duration
	retryPeriod   time.Duration

	// The lock object used to perform leader election for this selected service
	lock            *resourcelock.LeaseLock
	currentlyLeader bool
	leaderChannel   chan leaderElectionEvent

	// Leader election goroutine lifetime management
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func (ss *selectedService) serviceLeaderElection(ctx context.Context) error {
	defer close(ss.done)

	ss.ctx, ss.cancel = context.WithCancel(ctx)

	leaderelection.RunOrDie(ss.ctx, leaderelection.LeaderElectionConfig{
		Name:            ss.lock.LeaseMeta.Name,
		Lock:            ss.lock,
		ReleaseOnCancel: true,

		LeaseDuration: ss.leaseDuration,
		RenewDeadline: ss.renewDeadline,
		RetryPeriod:   ss.retryPeriod,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				ss.leaderChannel <- leaderElectionEvent{
					typ:             leaderElectionLeading,
					selectedService: ss,
				}
			},
			OnStoppedLeading: func() {
				ss.leaderChannel <- leaderElectionEvent{
					typ:             leaderElectionStoppedLeading,
					selectedService: ss,
				}
			},
		},
	})

	return nil
}

func (ss *selectedService) stop() {
	if ss.cancel != nil {
		ss.cancel()
		<-ss.done
		ss.currentlyLeader = false
	}
}

type leaderElectionEventType int

const (
	leaderElectionLeading leaderElectionEventType = iota
	leaderElectionStoppedLeading
)

type leaderElectionEvent struct {
	typ             leaderElectionEventType
	selectedService *selectedService
}

type selectedPolicy struct {
	policy *cilium_api_v2alpha1.CiliumL2AnnouncementPolicy
	// pre-compiled service selector
	serviceSelector labels.Selector
	// a cached list of network devices selected by this policy based on the regular expressions in the policy
	// and the latest known list of devices.
	selectedDevices []string
}
