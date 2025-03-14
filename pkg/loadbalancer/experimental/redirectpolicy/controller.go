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
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
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
	Writer             *experimental.Writer
	NetNSCookieSupport experimental.HaveNetNSCookieSupport
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

	cleanupFuncs := map[k8s.ServiceID]func(experimental.WriteTxn){}

	// Amount of time to wait before reprocessing.
	const waitTime = 100 * time.Millisecond

	// Grab table init watch channels for the inputs. Once they all
	// close the Table[desiredSkipLB] is marked initialized to allow
	// pruning.
	txn := c.p.DB.ReadTxn()
	_, podsInitWatch := c.p.Pods.Initialized(txn)
	_, lrpsInitWatch := c.p.LRPs.Initialized(txn)
	_, fesInitWatch := c.p.Writer.Frontends().Initialized(txn)
	initWatches := statedb.NewWatchSet()
	initWatches.Add(podsInitWatch, lrpsInitWatch, fesInitWatch)

	for {
		allWatches := statedb.NewWatchSet()

		if initWatches != nil {
			allWatches.Merge(initWatches)
		}

		// Start a write transaction against the load-balancing tables and the desired skip LB
		// table.
		wtxn := c.p.Writer.WriteTxn(c.p.DesiredSkipLB)

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
			if ws, cleanup := c.processLRP(wtxn, lrp.ID); ws != nil {
				allWatches.Merge(ws)
				watchSets[lrp.ID] = ws
				cleanupFuncs[lrp.ID] = cleanup
			}
		}

		// Process removed LRPs
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

		orphans = existing

		// Wait for any of the inputs to change.
		var err error
		closedWatches, err = allWatches.Wait(ctx, waitTime)
		if err != nil {
			return err
		}
	}
}

func (c *lrpController) processLRP(wtxn experimental.WriteTxn, lrpID k8s.ServiceID) (*statedb.WatchSet, func(experimental.WriteTxn)) {
	lrp, _, watch, found := c.p.LRPs.GetWatch(wtxn, lrpIDIndex.Query(lrpID))
	if !found {
		return nil, nil
	}
	ws := statedb.NewWatchSet()
	ws.Add(watch)

	cleanup := func(wtxn experimental.WriteTxn) {
		// Unset the redirect on all frontends.
		if lrp.LRPType == lrpConfigTypeSvc {
			targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
			for fe := range c.p.Writer.Frontends().List(wtxn, experimental.FrontendByServiceName(targetName)) {
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

	toName := lrp.ServiceName()

	// Create a frontendless pseudo-service for the redirect policy. The backends
	// will be associated with this service.
	if _, _, found := c.p.Writer.Services().Get(wtxn, experimental.ServiceByName(toName)); !found {
		_, err := c.p.Writer.UpsertService(wtxn,
			&experimental.Service{
				Name:             toName,
				Source:           source.Kubernetes,
				ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
				IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
			})
		if err != nil {
			// Currently there are no known errors that we expect to occur here.
			c.p.Log.Error("Failed to upsert local redirect pseudo-service",
				logfields.ServiceName, toName,
				logfields.Error, err)
		}
	}

	// NOTE: Redirect policies are immutable, so we don't need to unset redirects here.
	// If they were made mutable, we'd need to find each frontend that has a redirect to
	// the pseudo-service and remove the redirects from frontends that no longer match
	// the spec.

	switch lrp.LRPType {
	case lrpConfigTypeSvc:
		targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
		fes, watch := c.p.Writer.Frontends().ListWatch(wtxn, experimental.FrontendByServiceName(targetName))
		ws.Add(watch)
		for fe := range fes {
			// 1. Only ClusterIP services can be redirected.
			if fe.Type != lb.SVCTypeClusterIP {
				continue
			}

			// 2. First match the frontend based on "RedirectFrontend.ToPorts"
			// 2.2. All frontends match if no ports are given
			match := len(lrp.FrontendMappings) == 0

			// 2.2. Frontend matches if the port number matches
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
				c.p.Log.Debug("Skipping frontend due to frontend port mismatch",
					logfields.Frontend, fe,
					logfields.LRPFrontends, lrp.FrontendMappings)
				continue
			}

			// 3. Frontend matches if there is a matching backend. If there are none
			// then this frontend won't be redirected/blackholed even though "RedirectedFrontend.ToPorts"
			// matched.
			// 3.1. Frontend matches if there either are no backend ports specified or there is only single
			// port (as that doesn't need to be named).
			match = len(lrp.BackendPorts) <= 1

			// 3.2. Frontend matches if there is a backend whose port name matches.
			if !match {
				_, match = lrp.BackendPortsByPortName[fe.PortName]
			}

			if !match {
				// RedirectBackend.ToPorts mismatch, skip.
				c.p.Log.Debug("Skipping frontend due to backend port mismatch",
					logfields.Frontend, fe,
					logfields.LRPBackendPorts, lrp.BackendPorts)
				continue
			}

			c.p.Log.Debug("Redirecting frontend",
				logfields.Frontend, fe,
				logfields.ServiceName, targetName)
			c.p.Writer.SetRedirectTo(wtxn, fe, &toName)
		}

	case lrpConfigTypeAddr:
		// In address-based mode there is no existing service/frontend to match against and
		// instead the frontend is created here.
		for _, feM := range lrp.FrontendMappings {
			fe, _, found := c.p.Writer.Frontends().Get(wtxn, experimental.FrontendByAddress(feM.feAddr))
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
				experimental.FrontendParams{
					Address:     feM.feAddr,
					Type:        lb.SVCTypeLocalRedirect,
					ServiceName: toName,
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
	// service we just created.
	matchingPods, watch := c.p.Pods.PrefixWatch(wtxn, daemonk8s.PodByName(lrpID.Namespace, ""))
	ws.Add(watch)
	for pod := range matchingPods {
		if len(pod.Namespace) != len(lrp.ID.Namespace) {
			break
		}
		if lrp.BackendSelector.Matches(labels.Set(pod.Labels)) {
			c.processLRPAndPod(wtxn, ws, lrp, getPodInfo(pod))
		}
	}
	return ws, cleanup
}

func (c *lrpController) processLRPAndPod(wtxn experimental.WriteTxn, ws *statedb.WatchSet, lrp *LocalRedirectPolicy, podInfo podInfo) {
	c.updateSkipLB(wtxn, ws, lrp, podInfo)

	portNameMatches := func(portName string) bool {
		for bePortName := range lrp.BackendPortsByPortName {
			if string(bePortName) == strings.ToLower(portName) {
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
			continue
		}
		beps = append(beps, experimental.BackendParams{
			L3n4Addr:  addr.L3n4Addr,
			State:     lb.BackendStateActive,
			PortNames: []string{addr.portName},
		})
	}

	// Skip the backend update and refresh if the backends didn't actually change.
	newCount := len(beps)
	orphanCount := 0
	for be := range c.p.Writer.Backends().List(wtxn, experimental.BackendByServiceName(toName)) {
		if slices.ContainsFunc(beps, func(bep experimental.BackendParams) bool {
			return bep.L3n4Addr.DeepEqual(&be.L3n4Addr)
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
		toName,
		source.Kubernetes,
		beps...); err != nil {
		c.p.Log.Warn("updating backends failed",
			logfields.ServiceName, toName,
			logfields.Error, err)
		return
	}

	// Finally refresh the frontends of the redirected service to recalculate its backends.
	switch lrp.LRPType {
	case lrpConfigTypeSvc:
		targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
		c.p.Writer.RefreshFrontends(wtxn, targetName)
	}
}

func (c *lrpController) updateSkipLB(wtxn experimental.WriteTxn, ws *statedb.WatchSet, lrp *LocalRedirectPolicy, podInfo podInfo) {
	// Update the desired skiplb state. The Table[desiredSkipLB] holds all local endpoints filled in
	// from EndpointManager. We may see the endpoint first and thus have the netns cookie and can
	// reconcile immediately, or we may see LRP & pod first and thus have to wait for the EndpointManager
	// callback before reconciling.
	if c.p.NetNSCookieSupport() {
		skiplb, _, watch, found := c.p.DesiredSkipLB.GetWatch(wtxn, desiredSkipLBPodIndex.Query(podInfo.namespacedName))
		ws.Add(watch)

		if !lrp.SkipRedirectFromBackend {
			if !found || len(skiplb.SkipRedirectForFrontends) == 0 {
				// Nothing to do.
				return
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
			return
		}

		skiplb.SkipRedirectForFrontends = newRedirects
		if skiplb.NetnsCookie != nil {
			skiplb.Status = reconciler.StatusPending()
		}
		c.p.DesiredSkipLB.Insert(wtxn, skiplb)
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
	fes, watch := c.p.Writer.Frontends().ListWatch(txn, experimental.FrontendByServiceName(targetName))
	ws.Add(watch)
	for fe := range fes {
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
