// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func registerLRPController(g job.Group, p lrpControllerParams) {
	if !p.Enabled {
		return
	}
	// Register table initializer for Table[desiredSkipLB] to delay pruning
	// until we've processed the initial data sets.
	wtxn := p.Writer.WriteTxn(p.DesiredSkipLB)
	desiredSkipLBInit := p.DesiredSkipLB.RegisterInitializer(wtxn, "lrp-controller")
	wtxn.Commit()

	h := &lrpController{p: p, desiredSkipLBInit: desiredSkipLBInit}
	g.Add(job.OneShot("controller", h.run))
}

type lrpControllerParams struct {
	cell.In

	Enabled            lrpIsEnabled
	Log                *slog.Logger
	DB                 *statedb.DB
	LRPs               statedb.Table[*LocalRedirectPolicy]
	Pods               statedb.Table[daemonk8s.LocalPod]
	DesiredSkipLB      statedb.RWTable[*desiredSkipLB]
	Writer             *writer.Writer
	NetNSCookieSupport lbmaps.HaveNetNSCookieSupport
	Metrics            controllerMetrics
}

type lrpController struct {
	p                 lrpControllerParams
	desiredSkipLBInit func(statedb.WriteTxn)

	skipLBWarningLogged bool
}

// run processes LocalRedirectPolicies to:
//
//  1. create a pseudo-service (with suffix -local-redirect) with pods as backends and sets
//     redirects from matched services to the pseudo-service.
//
//  2. updates the Table[DesiredSkipLB] to reconcile changes to the SkipLBMap in order
//     to instruct BPF datapath to not perform load-balancing on traffic from the backend
//     pod to the redirected frontends (if SkipRedirectFromBackend is set).
func (c *lrpController) run(ctx context.Context, health cell.Health) error {
	watchSets := map[k8s.ServiceID]*statedb.WatchSet{}
	var closedWatches []<-chan struct{}
	orphans := sets.New[k8s.ServiceID]()

	// Functions to clean up the state from the redirect policy when it is removed.
	cleanupFuncs := map[k8s.ServiceID]func(writer.WriteTxn){}

	// Amount of time to wait before reprocessing. This reduces the overhead around
	// the WriteTxn and the WatchSet and avoids processing intermediate states of
	// objects.
	const waitTime = 100 * time.Millisecond

	// Grab table init watch channels for the inputs. Once they allclose the
	// Table[desiredSkipLB] is marked initialized to allow pruning the BPF map.
	txn := c.p.DB.ReadTxn()
	_, podsInitWatch := c.p.Pods.Initialized(txn)
	_, lrpsInitWatch := c.p.LRPs.Initialized(txn)
	_, fesInitWatch := c.p.Writer.Frontends().Initialized(txn)
	initWatches := statedb.NewWatchSet()
	initWatches.Add(podsInitWatch, lrpsInitWatch, fesInitWatch)

	for {
		t0 := time.Now()

		allWatches := statedb.NewWatchSet()

		if initWatches != nil {
			allWatches.Merge(initWatches)
		}

		// Start a write transaction against the load-balancing tables and the desired skip LB
		// table.
		wtxn := c.p.Writer.WriteTxn(c.p.DesiredSkipLB)

		// Process all redirect policies to compute which frontends to redirect to local pods
		// and which SkipLBMap entries to set.
		lrps, watch := c.p.LRPs.AllWatch(wtxn)
		allWatches.Add(watch)

		existing := sets.New[k8s.ServiceID]()
		for lrp := range lrps {
			existing.Insert(lrp.ID)
			orphans.Delete(lrp.ID)

			if ws, found := watchSets[lrp.ID]; found {
				// None of the inputs to this LRP have changed, skip.
				if !ws.HasAny(closedWatches) {
					allWatches.Merge(ws)
					continue
				}
			}
			// (re)compute the frontend redirects and SkipLB entries for this
			// policy.
			if ws, cleanup := c.processRedirectPolicy(wtxn, lrp.ID); ws != nil {
				allWatches.Merge(ws)
				watchSets[lrp.ID] = ws
				cleanupFuncs[lrp.ID] = cleanup
			}
		}

		// Process removed redirect policies.
		for lrpID := range orphans {
			if cleanup := cleanupFuncs[lrpID]; cleanup != nil {
				cleanup(wtxn)
			}
			delete(cleanupFuncs, lrpID)
		}

		// Mark Table[desiredSkipLB] initialized once we've processed all
		// input tables and they're initialized.
		if initWatches != nil {
			if chanIsClosed(podsInitWatch) &&
				chanIsClosed(lrpsInitWatch) &&
				chanIsClosed(fesInitWatch) {
				c.desiredSkipLBInit(wtxn)
				initWatches = nil
			}
		}

		wtxn.Commit()

		c.p.Metrics.ControllerDuration.Observe(float64(time.Since(t0)) / float64(time.Second))

		orphans = existing

		// Wait for any of the inputs to change.
		var err error
		closedWatches, err = allWatches.Wait(ctx, waitTime)
		if err != nil {
			return err
		}
	}
}

func (c *lrpController) processRedirectPolicy(wtxn writer.WriteTxn, lrpID k8s.ServiceID) (*statedb.WatchSet, func(writer.WriteTxn)) {
	lrp, _, watch, found := c.p.LRPs.GetWatch(wtxn, lrpIDIndex.Query(lrpID))
	if !found {
		return nil, nil
	}

	c.p.Log.Debug("Processing local redirect policy",
		logfields.LRPName, lrpID,
		logfields.LRPType, lrpConfigTypeString(lrp.LRPType),
		logfields.LRPFrontends, lrp.FrontendMappings,
		logfields.LRPLocalEndpointSelector, lrp.BackendSelector,
		logfields.LRPBackendPorts, lrp.BackendPorts,
		logfields.ServiceID, lrp.ServiceID,
	)

	// Construct a watch set from all the queries made during processing of this policy.
	// We reprocess this policy when any of its inputs change (watch channel closes).
	ws := statedb.NewWatchSet()
	ws.Add(watch)

	cleanup := func(wtxn writer.WriteTxn) {
		// Unset the redirect on all frontends.
		if lrp.LRPType == lrpConfigTypeSvc {
			targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
			for fe := range c.p.Writer.Frontends().List(wtxn, lb.FrontendByServiceName(targetName)) {
				c.p.Writer.SetRedirectTo(wtxn, fe, nil)
			}
		}

		// Remove the pseudo-service and the backends
		toName := lrpServiceName(lrpID)
		c.p.Writer.DeleteBackendsOfService(wtxn, toName, source.Kubernetes)
		c.p.Writer.DeleteServiceAndFrontends(wtxn, toName)

		// Clear the SkipLBs. Note that they're only deleted when the endpoint goes away.
		for dsl := range c.p.DesiredSkipLB.All(wtxn) {
			if dsl.LRPID == lrpID && dsl.SkipRedirectForFrontends != nil {
				dsl = dsl.clone()
				dsl.SkipRedirectForFrontends = nil
				dsl.Status = reconciler.StatusPending()
				c.p.DesiredSkipLB.Insert(wtxn, dsl)
			}
		}
	}

	// Create a "pseudo-service" for the redirect policy to which the pods are associated as
	// backends. The frontends of the target service will be redirected to this service and
	// will pick up the local pods as the new backends.
	// If the redirect policy is an "address matcher" then we will also create frontends for
	// this service.
	lrpServiceName := lrp.ServiceName()
	if _, _, found := c.p.Writer.Services().Get(wtxn, lb.ServiceByName(lrpServiceName)); !found {
		_, err := c.p.Writer.UpsertService(wtxn,
			&lb.Service{
				Name:             lrpServiceName,
				Source:           source.Kubernetes,
				ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
				IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
			})
		if err != nil {
			// Currently there are no known errors that we expect to occur here.
			c.p.Log.Error("Failed to upsert local redirect pseudo-service",
				logfields.ServiceName, lrpServiceName,
				logfields.Error, err)
		}
	}

	switch lrp.LRPType {
	case lrpConfigTypeSvc:
		// Find frontends associated with the target service that match the redirection criteria and
		// redirect them to the LRP "pseudo-service".
		targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
		fes, watch := c.p.Writer.Frontends().ListWatch(wtxn, lb.FrontendByServiceName(targetName))
		ws.Add(watch)
		for fe := range fes {
			// Only ClusterIP services can be redirected.
			if fe.Type != lb.SVCTypeClusterIP {
				continue
			}
			if shouldRedirectFrontend(c.p.Log, lrp, fe) {
				c.p.Log.Debug("Redirecting frontend",
					logfields.Frontend, fe,
					logfields.ServiceName, targetName,
					logfields.Target, &lrpServiceName)
				c.p.Writer.SetRedirectTo(wtxn, fe, &lrpServiceName)
			} else {
				c.p.Writer.SetRedirectTo(wtxn, fe, nil)
			}
		}

	case lrpConfigTypeAddr:
		// In address-based mode there is no existing service/frontend to match against and
		// instead the frontend is created here.
		for _, feM := range lrp.FrontendMappings {
			fe, _, found := c.p.Writer.Frontends().Get(wtxn, lb.FrontendByAddress(feM.feAddr))
			if found {
				if fe.Type != lb.SVCTypeLocalRedirect {
					c.p.Log.Error("LocalRedirectPolicy matches an address owned by an existing service => refusing to override",
						logfields.Address, feM.feAddr,
						logfields.ServiceName, fe.ServiceName)
				}
				continue
			}
			_, err := c.p.Writer.UpsertFrontend(
				wtxn,
				lb.FrontendParams{
					Address:     feM.feAddr,
					Type:        lb.SVCTypeLocalRedirect,
					ServiceName: lrpServiceName,
					ServicePort: feM.feAddr.Port,
				},
			)
			if err != nil {
				// Not expecting any errors here as the address conflict already handled above.
				c.p.Log.Error("Failed to upsert frontend for LocalRedirectPolicy",
					logfields.LRPName, lrp.ID,
					logfields.Address, feM.feAddr,
					logfields.Error, err)
			}
		}
	}

	// For each matching pod create a backend and associate it with the LocalRedirect
	// service we just created above. We find pods by doing a prefix search with the
	// namespace (more efficient than having a separate namespace index for pods).
	podsSameNamespace, watch := c.p.Pods.PrefixWatch(wtxn, daemonk8s.PodByName(lrpID.Namespace, ""))
	ws.Add(watch)

	var matchingPods []podInfo
	for pod := range podsSameNamespace {
		if len(pod.Namespace) != len(lrp.ID.Namespace) {
			// Stop when we hit a different namespace, e.g. prefix search hit a longer name.
			break
		}
		if lrp.BackendSelector.Matches(labels.Set(pod.Labels)) {
			matchingPods = append(matchingPods, getPodInfo(pod))
		}
	}
	c.updateRedirectBackends(wtxn, ws, lrp, matchingPods)
	c.updateSkipLB(wtxn, ws, lrp, matchingPods)
	return ws, cleanup
}

func (c *lrpController) updateRedirectBackends(wtxn writer.WriteTxn, ws *statedb.WatchSet, lrp *LocalRedirectPolicy, pods []podInfo) {
	portNameMatches := func(portName string) bool {
		for bePortName := range lrp.BackendPortsByPortName {
			if string(bePortName) == strings.ToLower(portName) {
				return true
			}
		}
		return false
	}

	// Port name checks can be skipped in certain cases.
	switch lrp.FrontendType {
	case svcFrontendAll, svcFrontendSinglePort, addrFrontendSinglePort:
		portNameMatches = nil

	}

	// Construct the BackendParams from matching pods.
	beps := make([]lb.BackendParams, 0, len(pods))
	lrpServiceName := lrp.ServiceName()
	for _, podInfo := range pods {
		for _, addr := range podInfo.addrs {
			if portNameMatches != nil && !portNameMatches(addr.portName) {
				continue
			}
			beps = append(beps, lb.BackendParams{
				Address:   addr.L3n4Addr,
				State:     lb.BackendStateActive,
				PortNames: []string{addr.portName},
			})
		}
	}

	// Validate whether an update is actually needed to avoid no-op changes to the tables.
	newCount := len(beps)
	orphanCount := 0
	for be := range c.p.Writer.Backends().List(wtxn, lb.BackendByServiceName(lrpServiceName)) {
		if slices.ContainsFunc(beps, func(bep lb.BackendParams) bool {
			return bep.Address.DeepEqual(&be.Address)
		}) {
			newCount--
		} else {
			orphanCount++
		}
	}
	if orphanCount == 0 && newCount == 0 {
		return
	}

	if err := c.p.Writer.SetBackends(
		wtxn,
		lrpServiceName,
		source.Kubernetes,
		beps...); err != nil {
		c.p.Log.Warn("updating backends failed",
			logfields.ServiceName, lrpServiceName,
			logfields.Error, err)
		return
	}

	// Finally refresh the frontends of the redirected service to recalculate its backends.
	//
	// If the LRP is an address matcher, then lrpServiceName == targetName and we already
	// refreshed the frontend via SetBackends() above.
	if lrp.LRPType == lrpConfigTypeSvc {
		targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
		c.p.Writer.RefreshFrontends(wtxn, targetName)
	}
}

func shouldRedirectFrontend(log *slog.Logger, lrp *LocalRedirectPolicy, fe *lb.Frontend) bool {
	// 1. First match the frontend based on "RedirectFrontend.ToPorts"
	// 1.1. All frontends match if no ports are given
	match := len(lrp.FrontendMappings) == 0

	// 1.2. Frontend matches if the port number matches
	if !match {
		for _, feM := range lrp.FrontendMappings {
			match = feM.feAddr.L4Addr.Port == fe.Address.Port && feM.feAddr.L4Addr.Protocol == fe.Address.Protocol
			if match {
				break
			}
		}
	}
	if !match {
		// RedirectFrontend.ToPorts mismatch, skip.
		if log != nil {
			log.Debug("Skipping frontend due to frontend port mismatch",
				logfields.Frontend, fe,
				logfields.LRPFrontends, lrp.FrontendMappings)
		}
		return false
	}

	// 2. Frontend matches if there is a matching backend. If there are none
	// then this frontend won't be redirected/blackholed even though "RedirectedFrontend.ToPorts"
	// matched.
	// 2.1. Frontend matches if there either are no backend ports specified or there is only
	// single port (as that doesn't need to be named).
	match = len(lrp.BackendPorts) <= 1

	// 2.2. Frontend matches if there is a backend whose port name matches.
	if !match {
		_, match = lrp.BackendPortsByPortName[fe.PortName]
	}

	if !match {
		// RedirectBackend.ToPorts mismatch, skip.
		if log != nil {
			log.Debug("Skipping frontend due to backend port mismatch",
				logfields.Frontend, fe,
				logfields.LRPBackendPorts, lrp.BackendPorts)
		}
		return false
	}

	return true
}

func (c *lrpController) updateSkipLB(wtxn writer.WriteTxn, ws *statedb.WatchSet, lrp *LocalRedirectPolicy, pods []podInfo) {
	// Update the desired skiplb state. The Table[desiredSkipLB] holds all local endpoints filled in
	// from EndpointManager. We may see the endpoint first and thus have the netns cookie and can
	// reconcile immediately, or we may see LRP & pod first and thus have to wait for the EndpointManager
	// callback before reconciling.
	if c.p.NetNSCookieSupport() {
		existingSkipLBs, watch := c.p.DesiredSkipLB.ListWatch(wtxn, desiredSkipLBLRPIndex.Query(lrp.ID))
		ws.Add(watch)

		orphans := sets.New[string]()
		for dsl := range existingSkipLBs {
			if dsl.SkipRedirectForFrontends != nil {
				orphans.Insert(dsl.PodNamespacedName)
			}
		}

		for _, podInfo := range pods {
			orphans.Delete(podInfo.namespacedName)

			skiplb, _, watch, found := c.p.DesiredSkipLB.GetWatch(wtxn, desiredSkipLBPodIndex.Query(podInfo.namespacedName))
			ws.Add(watch)

			if !lrp.SkipRedirectFromBackend {
				if !found || len(skiplb.SkipRedirectForFrontends) == 0 {
					// Nothing to do.
					continue
				}
			}

			toName := lrp.ServiceName()
			if found {
				skiplb = skiplb.clone()
			} else {
				skiplb = newDesiredSkipLB(lrp.ID, podInfo.namespacedName)
			}

			newRedirects := maps.Clone(skiplb.SkipRedirectForFrontends)
			if newRedirects == nil {
				newRedirects = map[lb.ServiceName][]lb.L3n4Addr{}
			}
			newRedirects[toName] = c.frontendsToSkip(wtxn, ws, lrp)

			if skipRedirectsEqual(skiplb.SkipRedirectForFrontends, newRedirects) {
				continue
			}

			skiplb.LRPID = lrp.ID
			skiplb.SkipRedirectForFrontends = newRedirects
			if skiplb.NetnsCookie != nil {
				skiplb.Status = reconciler.StatusPending()
			}
			c.p.DesiredSkipLB.Insert(wtxn, skiplb)
		}

		for podName := range orphans {
			dsl, _, found := c.p.DesiredSkipLB.Get(wtxn, desiredSkipLBPodIndex.Query(podName))
			if found {
				dsl = dsl.clone()
				dsl.SkipRedirectForFrontends = nil
				dsl.Status = reconciler.StatusPending()
				c.p.DesiredSkipLB.Insert(wtxn, dsl)
			}
		}
	} else if !c.skipLBWarningLogged {
		c.p.Log.Warn("LocalRedirectPolicy with SkipRedirectFromBackend cannot be applied, needs kernel version >= 5.12")
		c.skipLBWarningLogged = true
	}
}

func (c *lrpController) frontendsToSkip(txn statedb.ReadTxn, ws *statedb.WatchSet, lrp *LocalRedirectPolicy) []lb.L3n4Addr {
	if !lrp.SkipRedirectFromBackend {
		return nil
	}

	var targetName lb.ServiceName
	if lrp.LRPType == lrpConfigTypeAddr {
		// For address-based matching we created the frontends, so we look up from the pseudo-service
		targetName = lrp.ServiceName()
	} else {
		targetName = lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
	}

	feAddrs := []lb.L3n4Addr{}
	fes, watch := c.p.Writer.Frontends().ListWatch(txn, lb.FrontendByServiceName(targetName))
	ws.Add(watch)
	for fe := range fes {
		if lrp.LRPType == lrpConfigTypeAddr || fe.RedirectTo != nil {
			feAddrs = append(feAddrs, fe.Address)
		}
	}
	return feAddrs
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

func chanIsClosed(ch <-chan struct{}) bool {
	select {
	case _, ok := <-ch:
		return !ok
	default:
		return false
	}
}
