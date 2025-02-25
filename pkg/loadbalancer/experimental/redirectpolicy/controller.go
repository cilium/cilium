// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"log/slog"
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const localRedirectSvcStr = "-local-redirect"

type lrpIsEnabled bool

func newLRPIsEnabled(expConfig experimental.Config, daemonConfig *option.DaemonConfig) lrpIsEnabled {
	return lrpIsEnabled(
		expConfig.EnableExperimentalLB && daemonConfig.EnableLocalRedirectPolicy,
	)
}

type lrpControllerParams struct {
	cell.In

	Enabled            lrpIsEnabled
	Log                *slog.Logger
	DB                 *statedb.DB
	LRPs               statedb.Table[*LocalRedirectPolicy]
	Pods               statedb.Table[daemonk8s.LocalPod]
	DesiredSkipLB      statedb.RWTable[*desiredSkipLB]
	Writer             *experimental.Writer
	NetNSCookieSupport experimental.HaveNetNSCookieSupport
}

type lrpController struct {
	p lrpControllerParams

	skipLBWarningLogged bool
}

// podInfo is the condensed data from the pod relevant for the LRP processing.
type podInfo struct {
	namespace      string
	namespacedName string
	addrs          []podAddr
	labels         map[string]string
}

func getPodInfo(pod daemonk8s.LocalPod) podInfo {
	return podInfo{
		namespace:      pod.Namespace,
		namespacedName: pod.Namespace + "/" + pod.Name,
		addrs:          podAddrs(pod.Pod),
		labels:         pod.Labels,
	}
}

// run processes changes to Table[LocalRedirectPolicy], Table[LocalPod] and Table[Frontend]
// and 1) creates pseudo-service (with suffix -local-redirect) with pods as backends and sets
// redirects from matched services to the pseudo-service, 2) updates the Table[DesiredSkipLB]
// to reconcile changes to the SkipLBMap in order to instruct BPF datapath to not perform
// load-balancing from the backend pod to the redirected frontends (if SkipRedirectFromBackend is set).
func (c *lrpController) run(ctx context.Context, health cell.Health) error {
	wtxn := c.p.DB.WriteTxn(c.p.LRPs, c.p.Pods, c.p.Writer.Frontends(), c.p.DesiredSkipLB)
	defer wtxn.Abort()

	lrps, err := c.p.LRPs.Changes(wtxn)
	if err != nil {
		return err
	}

	pods, err := c.p.Pods.Changes(wtxn)
	if err != nil {
		return err
	}

	frontends, err := c.p.Writer.Frontends().Changes(wtxn)
	if err != nil {
		return err
	}

	desiredSkipLBInit := c.p.DesiredSkipLB.RegisterInitializer(wtxn, "controller")
	_, podsInitWatch := c.p.Pods.Initialized(wtxn)
	_, lrpsInitWatch := c.p.LRPs.Initialized(wtxn)
	_, fesInitWatch := c.p.Writer.Frontends().Initialized(wtxn)

	wtxn.Commit()

	// Limit the rate at which the changes are processed. This allows processing in
	// larger batches and skipping intermediate states of the objects.
	limiter := rate.NewLimiter(100*time.Millisecond, 1)
	defer limiter.Stop()

	for {
		health.OK("Processing changes")

		// Write transaction against the load-balancing tables and the desired-skiplb table.
		wtxn := c.p.Writer.WriteTxn(c.p.DesiredSkipLB)

		lrpChanges, lrpWatch := lrps.Next(wtxn)
		// Process the changed local redirect policies. Find frontends that should be redirected
		// and find mathed pods from which to create backends.
		for change := range lrpChanges {
			lrp := change.Object
			toName := lrp.ServiceName()

			if change.Deleted {
				c.p.Writer.DeleteServiceAndFrontends(wtxn, toName)
			} else {
				// Create a frontendless pseudo-service for the redirect policy. The backends
				// will be associated with this service.
				c.p.Writer.UpsertService(wtxn,
					&experimental.Service{
						Name:             toName,
						Source:           source.Kubernetes,
						ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
						IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
					},
				)
			}

			// NOTE: Redirect policies are immutable, so we don't need to unset redirects here.
			// If they were made mutable, we'd need to find each frontend that has a redirect to
			// the pseudo-service and remove the redirects from frontends that no longer match
			// the spec.

			switch lrp.LRPType {
			case lrpConfigTypeSvc:
				targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
				if !change.Deleted {
					c.p.Writer.SetRedirectToByName(wtxn, targetName, &toName)
				} else {
					c.p.Writer.SetRedirectToByName(wtxn, targetName, nil)
				}
			case lrpConfigTypeAddr:
				// In address-based mode there is no existing service/frontend to match against, but rather we'll
				// create the frontend here.
				if !change.Deleted {
					for _, feM := range lrp.FrontendMappings {
						_, err := c.p.Writer.UpsertFrontend(
							wtxn,
							experimental.FrontendParams{
								Address:     feM.feAddr,
								Type:        lb.SVCTypeLocalRedirect,
								ServiceName: toName,
								ServicePort: feM.feAddr.Port,
							},
						)
						if err != nil {
							// Error may occur when a frontend already exists as part of some other
							// service.
							c.p.Log.Warn("failed to upsert frontend", logfields.Error, err)
						}
					}
				}
			}

			// Find pods that match with the LRP
			if !change.Deleted {
				matchingPods := c.p.Pods.Prefix(wtxn, daemonk8s.PodByName(lrp.ID.Namespace, ""))
				for pod := range matchingPods {
					if len(pod.Namespace) != len(lrp.ID.Namespace) {
						break
					}
					if lrp.BackendSelector.Matches(labels.Set(pod.Labels)) {
						c.processLRPAndPod(wtxn, lrp, getPodInfo(pod))
					}
				}
			}
		}

		// Process changed pods and find matching LRPs and add the pods as backends.
		podChanges, podWatch := pods.Next(wtxn)
		for change := range podChanges {
			if !change.Deleted &&
				k8sUtils.GetLatestPodReadiness(change.Object.Status) != slim_corev1.ConditionTrue {
				// Ignore pods that are not yet ready.
				continue
			}

			podInfo := getPodInfo(change.Object)

			// Find LRPs in the same namespace that match with this pod.
			matchingLRPs := c.p.LRPs.Prefix(wtxn, lrpIDIndex.Query(k8s.ServiceID{Namespace: podInfo.namespace}))
			for lrp := range matchingLRPs {
				if len(lrp.ID.Namespace) != len(podInfo.namespace) {
					// Different (longer) namespace, stop here.
					break
				}
				if lrp.BackendSelector.Matches(labels.Set(podInfo.labels)) {
					if change.Deleted {
						toName := lrp.ServiceName()
						for _, addr := range podInfo.addrs {
							c.p.Writer.ReleaseBackend(wtxn, toName, addr.L3n4Addr)
						}
					} else {
						c.processLRPAndPod(wtxn, lrp, podInfo)
					}
				}
			}
		}

		// Process changes to service frontends to find if any redirect policy matches on them
		// and set the redirects accordingly.
		frontendChanges, frontendWatch := frontends.Next(wtxn)
		for change := range frontendChanges {
			fe := change.Object
			if change.Deleted {
				continue
			}

			serviceID := k8s.ServiceID{
				Namespace: fe.ServiceName.Namespace,
				Name:      fe.ServiceName.Name,
			}

			lrp, _, found := c.p.LRPs.Get(wtxn, lrpServiceIndex.Query(serviceID))
			if !found {
				continue
			}

			// A local redirect policy matches this frontend, set the redirect.
			toName := lrp.ServiceName()
			targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
			if fe.RedirectTo != nil && fe.RedirectTo.Equal(targetName) {
				// Redirect already set, nothing to do.
				continue
			}
			c.p.Writer.SetRedirectToByName(wtxn, targetName, &toName)
		}

		if desiredSkipLBInit != nil {
			if podsInitWatch == nil && lrpsInitWatch == nil && fesInitWatch == nil {
				// All the relevant input tables have initialized and we've processed the changes,
				// mark the Table[*desiredSkipLB] also as initialized to initiate pruning of stale
				// data.
				desiredSkipLBInit(wtxn)
				desiredSkipLBInit = nil
			}
		}

		wtxn.Commit()

		health.OK("Waiting for changes")

		// Rate limit the processing of the changes to increase efficiency.
		if err := limiter.Wait(ctx); err != nil {
			// Context cancelled, shutting down.
			return nil
		}

		select {
		case <-lrpWatch:
		case <-podWatch:
		case <-frontendWatch:
		case <-podsInitWatch:
			podsInitWatch = nil
		case <-fesInitWatch:
			fesInitWatch = nil
		case <-lrpsInitWatch:
			lrpsInitWatch = nil
		case <-ctx.Done():
			return nil
		}

	}
}

func (c *lrpController) processLRPAndPod(wtxn experimental.WriteTxn, lrp *LocalRedirectPolicy, podInfo podInfo) {
	c.p.Log.Info("processLRPAndPod",
		logfields.ID, lrp.ID,
		logfields.Pod, podInfo.namespacedName)

	portNameMatches := func(portName string) bool {
		for bePortName := range lrp.BackendPortsByPortName {
			if bePortName == portName {
				return true
			}
		}
		return false
	}

	// Port name checks can be skipped in certain cases.
	switch {
	case lrp.FrontendType == svcFrontendAll:
		fallthrough
	case lrp.FrontendType == svcFrontendSinglePort:
		fallthrough
	case lrp.FrontendType == addrFrontendSinglePort:
		portNameMatches = nil

	}

	toName := lrp.ServiceName()

	beps := make([]experimental.BackendParams, 0, len(podInfo.addrs))
	for _, addr := range podInfo.addrs {
		if portNameMatches != nil && !portNameMatches(addr.portName) {
			c.p.Log.Info("Mismatching port name",
				logfields.PortName, addr.portName,
				logfields.LRPFrontendType, lrp.FrontendType,
			)
			continue
		}
		beps = append(beps, experimental.BackendParams{
			L3n4Addr:  addr.L3n4Addr,
			State:     lb.BackendStateActive,
			PortNames: []string{addr.portName},
		})
		c.p.Log.Info("Adding backend instance", logfields.Name, toName)
	}
	c.p.Writer.SetBackends(
		wtxn,
		toName,
		source.Kubernetes,
		beps...,
	)

	// Update the desired skiplb state. The Table[desiredSkipLB] holds all local endpoints filled in
	// from EndpointManager. We may see the endpoint first and thus have the netns cookie and can
	// reconcile immediately, or we may see LRP & pod first and thus have to wait for the EndpointManager
	// callback before reconciling.
	if c.p.NetNSCookieSupport() {
		skiplb, _, found := c.p.DesiredSkipLB.Get(wtxn, desiredSkipLBPodIndex.Query(podInfo.namespacedName))
		if found {
			skiplb = skiplb.clone()
		} else {
			skiplb = newDesiredSkipLB(podInfo.namespacedName)
		}

		if skiplb.SkipRedirectForFrontends == nil {
			skiplb.SkipRedirectForFrontends = map[lb.ServiceName][]lb.L3n4Addr{}
		} else {
			skiplb.SkipRedirectForFrontends = maps.Clone(skiplb.SkipRedirectForFrontends)
		}
		skiplb.SkipRedirectForFrontends[toName] = c.frontendsToSkip(wtxn, lrp)
		if skiplb.NetnsCookie != nil {
			skiplb.Status = reconciler.StatusPending()
		}
		c.p.DesiredSkipLB.Insert(wtxn, skiplb)
	} else if lrp.SkipRedirectFromBackend && !c.skipLBWarningLogged {
		c.p.Log.Warn("LocalRedirectPolicy with SkipRedirectFromBackend cannot be applied, needs kernel version >= 5.12")
		c.skipLBWarningLogged = true
	}

	// Finally refresh the frontends of the redirected service to recalculate its backends.
	switch lrp.LRPType {
	case lrpConfigTypeSvc:
		targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
		c.p.Writer.RefreshFrontends(wtxn, targetName)
	case lrpConfigTypeAddr:
		c.p.Writer.RefreshFrontends(wtxn, toName)
	}
}

func (c *lrpController) frontendsToSkip(txn statedb.ReadTxn, lrp *LocalRedirectPolicy) []lb.L3n4Addr {
	var targetName lb.ServiceName
	if lrp.LRPType == lrpConfigTypeAddr {
		// For address-based matching we created the frontends, so we look up from the pseudo-service
		targetName = lrp.ServiceName()
	} else {
		targetName = lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
	}

	if !lrp.SkipRedirectFromBackend {
		return nil
	}
	feAddrs := []lb.L3n4Addr{}
	for fe := range c.p.Writer.Frontends().List(txn, experimental.FrontendByServiceName(targetName)) {
		if len(lrp.FrontendMappings) > 0 {
			skip := false
			for _, addr := range lrp.FrontendMappings {
				if lrp.LRPType == lrpConfigTypeAddr {
					if !addr.feAddr.DeepEqual(&fe.Address) {
						skip = true
						break
					}
				} else {
					if addr.feAddr.Port != fe.Address.Port {
						skip = true
						break
					}
					if addr.fePort != "" && string(fe.PortName) != addr.fePort {
						skip = true
						break
					}
				}
			}
			if skip {
				continue
			}
		}
		feAddrs = append(feAddrs, fe.Address)
	}
	return feAddrs
}

func (lrp *LocalRedirectPolicy) ServiceName() lb.ServiceName {
	return lb.ServiceName{Name: lrp.ID.Name + localRedirectSvcStr, Namespace: lrp.ID.Namespace}
}

type podAddr struct {
	lb.L3n4Addr
	portName string
}

func podAddrs(pod *slim_corev1.Pod) (addrs []podAddr) {
	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) == 0 {
		// IPs not available yet.
		return nil
	}
	for _, podIP := range podIPs {
		addrCluster, err := cmtypes.ParseAddrCluster(podIP)
		if err != nil {
			continue
		}
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				l4addr := lb.NewL4Addr(lb.L4Type(port.Protocol), uint16(port.ContainerPort))
				addr := podAddr{
					L3n4Addr: lb.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr:      *l4addr,
						Scope:       0,
					},
					portName: port.Name,
				}
				addrs = append(addrs, addr)
			}
		}
	}
	return
}

func registerLRPController(g job.Group, p lrpControllerParams) {
	if !p.Enabled {
		return
	}
	h := &lrpController{p: p}
	g.Add(job.OneShot("controller", h.run))
}
