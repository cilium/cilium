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

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const lrpControllerInitName = "lrp-controller"

func registerLRPController(g job.Group, p lrpControllerParams) {
	if !p.Enabled {
		return
	}

	// Register load-balancing initializer. This will also delay initial
	// endpoint regeneration until we're done.
	lbInit := p.Writer.RegisterInitializer(lrpControllerInitName)

	// Register table initializer for Table[desiredSkipLB] to delay pruning
	// until we've processed the initial data sets.
	wtxn := p.DB.WriteTxn(p.DesiredSkipLB)
	desiredSkipLBInit := p.DesiredSkipLB.RegisterInitializer(wtxn, lrpControllerInitName)
	wtxn.Commit()

	h := &lrpController{p: p, desiredSkipLBInit: desiredSkipLBInit, lbInit: lbInit}
	g.Add(job.OneShot("controller", h.run))
}

type lrpControllerParams struct {
	cell.In

	Enabled            lrpIsEnabled
	Log                *slog.Logger
	DB                 *statedb.DB
	LRPs               statedb.Table[*LocalRedirectPolicy]
	Pods               statedb.Table[k8sTables.LocalPod]
	DesiredSkipLB      statedb.RWTable[*desiredSkipLB]
	Writer             *writer.Writer
	NetNSCookieSupport reflectors.HaveNetNSCookieSupport
	Metrics            controllerMetrics
	LRPMetrics         LRPMetrics `optional:"true"`
}

type lrpController struct {
	p                 lrpControllerParams
	desiredSkipLBInit func(statedb.WriteTxn)
	lbInit            func(writer.WriteTxn)

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
	watchSets := map[lb.ServiceName]*statedb.WatchSet{}
	var closedWatches []<-chan struct{}

	// Keep track of which LRPs exist across the reconciliation rounds.
	orphans := sets.New[lb.ServiceName]()

	// Functions to clean up the state from the redirect policy when it is removed.
	cleanupFuncs := map[lb.ServiceName]func(writer.WriteTxn){}

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

		// Keep track of which LRPs now exist. This becomes the new [orphans] for the next round.
		existing := sets.New[lb.ServiceName]()

		for lrp := range lrps {
			if c.p.LRPMetrics != nil && !existing.Has(lrp.ID) {
				c.p.LRPMetrics.AddLRPConfig(lrp.ID)
			}

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
			delete(watchSets, lrpID)
			if c.p.LRPMetrics != nil {
				c.p.LRPMetrics.DelLRPConfig(lrpID)
			}
		}

		if initWatches != nil {
			if chanIsClosed(podsInitWatch) &&
				chanIsClosed(lrpsInitWatch) {

				// Mark load-balancing state initialized now that pods and LRPs have been
				// processed. We can't wait for frontends to initialize since we're one
				// of the initializers.
				c.lbInit(wtxn)

				if chanIsClosed(fesInitWatch) {
					// Mark desired SkipLBs as initialized to allow pruning
					c.desiredSkipLBInit(wtxn)

					// All initializers marked done, we can stop tracking these.
					initWatches = nil
				}
			}
		}

		wtxn.Commit()

		c.p.Metrics.ControllerDuration.Observe(float64(time.Since(t0)) / float64(time.Second))

		// Remember the currently existing LRPs as the potential orphans in the next round.
		orphans = existing

		// Wait for any of the inputs to change.
		var err error
		closedWatches, err = allWatches.Wait(ctx, waitTime)
		if err != nil {
			return err
		}
	}
}

func (c *lrpController) processRedirectPolicy(wtxn writer.WriteTxn, lrpID lb.ServiceName) (*statedb.WatchSet, func(writer.WriteTxn)) {
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
			targetName := lrp.ServiceID
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
	lrpServiceName := lrp.RedirectServiceName()
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

	// For each matching pod create a backend and associate it with the LocalRedirect
	// service we just created above. We find pods by doing a prefix search with the
	// namespace (more efficient than having a separate namespace index for pods).
	podsSameNamespace, watch := c.p.Pods.PrefixWatch(wtxn, k8sTables.PodByName(lrpID.Namespace(), ""))
	ws.Add(watch)

	var matchingPods []podInfo
	for pod := range podsSameNamespace {
		if len(pod.Namespace) != len(lrp.ID.Namespace()) {
			// Stop when we hit a different namespace, e.g. prefix search hit a longer name.
			break
		}
		if k8sUtils.GetLatestPodReadiness(pod.Status) != slim_corev1.ConditionTrue {
			continue
		}
		if types.Matches(lrp.BackendSelector, ciliumLabels.K8sSet(pod.Labels)) {
			matchingPods = append(matchingPods, getPodInfo(pod))
		}
	}
	c.updateRedirectBackends(wtxn, lrp, matchingPods)
	c.updateSkipLB(wtxn, ws, lrp, matchingPods)
	c.updateRedirects(wtxn, ws, cleanup, lrp, matchingPods)

	return ws, cleanup
}

func (c *lrpController) updateRedirects(wtxn writer.WriteTxn, ws *statedb.WatchSet, cleanup func(writer.WriteTxn), lrp *LocalRedirectPolicy, pods []podInfo) func(writer.WriteTxn) {
	lrpServiceName := lrp.RedirectServiceName()
	switch lrp.LRPType {
	case lrpConfigTypeSvc:
		lrpServiceAddrs := sets.New[lb.L3n4Addr]()
		numFrontendMappings := len(lrp.FrontendMappings)

		cacheFrontendAddr := func(fe *lb.Frontend) bool {
			if !lrp.isSinglePort() || numFrontendMappings == 0 {
				return false
			}

			// If frontend port matches the LRP frontend mapping, we don't need to
			// cache this address because there must already be a frontend.
			lrpAddr := lrp.FrontendMappings[0].feAddr
			if lrpAddr.Compatible(fe.Address) && lrpAddr.Port() == fe.Address.Port() {
				return false
			}

			// Insert a new address into the lrpServiceAddr set, using the protocol, port and
			// scope from the LRP frontend mapping, but the IP address of the matched service.
			lrpServiceAddrs.Insert(lb.NewL3n4Addr(
				lrpAddr.Protocol(),
				fe.Address.AddrCluster(),
				lrpAddr.Port(),
				lrpAddr.Scope(),
			))
			return true
		}

		// Find frontends associated with the target service that match the redirection criteria and
		// redirect them to the LRP "pseudo-service".
		targetName := lrp.ServiceID
		fes, watch := c.p.Writer.Frontends().ListWatch(wtxn, lb.FrontendByServiceName(targetName))
		ws.Add(watch)

		for fe := range fes {
			// Only ClusterIP services can be redirected.
			if fe.Type != lb.SVCTypeClusterIP {
				continue
			}

			// In the case of single-port LRPs, it's possible the frontend toPorts is filtered,
			// and the port does does not actually reflect any existing service. For example,
			// if a Service frontend is TCP/80 but the LRP toPorts is TCP/8080. Cache this fe
			// address, substituting the feMapping[0] port, so we can upsert a new frontend later.
			cacheFrontendAddr(fe)

			if shouldRedirectFrontend(c.p.Log, lrp, fe, pods) {
				c.p.Log.Debug("Redirecting frontend",
					logfields.Frontend, fe,
					logfields.ServiceName, targetName,
					logfields.Target, &lrpServiceName)
				c.p.Writer.SetRedirectTo(wtxn, fe, &lrpServiceName)
			} else {
				c.p.Writer.SetRedirectTo(wtxn, fe, nil)
			}
		}

		// Iterate over the cached LRP frontend addresses and identify if we need to
		// upsert any frontends. As noted above, this will likely be in scenarios where
		// single-port LRPs that use a different port to that of the underlying service.
		for lrpAddr := range lrpServiceAddrs {
			_, _, found := c.p.Writer.Frontends().Get(wtxn, lb.FrontendByAddress(lrpAddr))
			if !found {
				_, err := c.p.Writer.UpsertFrontend(
					wtxn,
					lb.FrontendParams{
						Address:     lrpAddr,
						Type:        lb.SVCTypeLocalRedirect,
						ServiceName: lrpServiceName,
						ServicePort: lrpAddr.Port(),
						PortName:    lb.FEPortName(""),
					},
				)
				if err != nil {
					c.p.Log.Error("Failed to upsert frontend for LocalRedirectPolicy",
						logfields.LRPName, lrp.ID,
						logfields.Address, lrpAddr,
						logfields.Error, err)
				}
			}
		}

	case lrpConfigTypeAddr:
		// In address-based mode there is no existing service/frontend to match against and
		// instead the frontend is created here.
		for _, feM := range lrp.FrontendMappings {
			fe, _, found := c.p.Writer.Frontends().Get(wtxn, lb.FrontendByAddress(feM.feAddr))
			if len(pods) == 0 {
				// No pods exist to redirect the traffic to. If we previously installed a
				// LocalRedirect frontend for this LRP, remove it so traffic falls back to
				// the original service. Never touch a frontend owned by another service.
				if found && fe.Type == lb.SVCTypeLocalRedirect && fe.ServiceName.Equal(lrpServiceName) {
					c.p.Writer.DeleteFrontend(wtxn, feM.feAddr)
				}
			} else {
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
						ServicePort: feM.feAddr.Port(),
						// if we only have one frontend mapping, we dont need the frontend port name so it will not check the port name in the backend ports
						PortName: func() lb.FEPortName {
							if len(lrp.FrontendMappings) > 1 {
								return feM.fePort
							}
							return lb.FEPortName("")
						}(),
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
	case lrpConfigTypeNone:
		cleanup(wtxn)
		return func(writer.WriteTxn) {}
	}
	return cleanup
}

func (c *lrpController) updateRedirectBackends(wtxn writer.WriteTxn, lrp *LocalRedirectPolicy, pods []podInfo) {
	portNameMatches := func(portName string) bool {
		for bePortName := range lrp.BackendPortsByPortName {
			if string(bePortName) == strings.ToLower(portName) {
				return true
			}
		}
		return false
	}

	// Port name checks can be skipped in certain cases.
	if !lrp.requiresPortNameMatch() {
		portNameMatches = nil
	}

	// Function to compare whether the new Backend produced in the loop below
	// is equal to the old one. We only compare subset of fields as some of the fields
	// are managed by the load-balancing control-plane.
	compareBackendParams := func(a, b *lb.Backend) bool {
		return a.Address == b.Address &&
			a.State == b.State &&
			slices.Equal(a.PortNames, b.PortNames)
	}

	// Construct the Backend from matching pods.
	beps := make([]lb.Backend, 0, len(pods))

	lrpIncludesBackendPort := func(addr lb.L3n4Addr) bool {
		// In the case of a single-port LRP, only compare against the first backend port.
		if lrp.isSinglePort() {
			return lrp.BackendPorts[0].l4Addr.Port == addr.Port() &&
				lrp.BackendPorts[0].l4Addr.Protocol == addr.Protocol()
		}
		return slices.ContainsFunc(lrp.BackendPorts, func(p bePortInfo) bool {
			return p.l4Addr.Port == addr.Port() && p.l4Addr.Protocol == addr.Protocol()
		})
	}

	appendBackend := func(be lb.Backend) {
		if portNameMatches != nil && !slices.ContainsFunc(be.PortNames, portNameMatches) {
			return
		}
		if !lrpIncludesBackendPort(be.Address) {
			return
		}

		bePortNames := []string{}

		// If we're not matching port names, we don't clone the backend port name.
		// Otherwise, the loadbalancer Writer will include the portName when mapping
		// backends to our LRP pseudo-service.
		if portNameMatches != nil {
			bePortNames = slices.Clone(be.PortNames)
		}

		beps = append(beps, lb.Backend{
			Address:   be.Address,
			State:     be.State,
			PortNames: bePortNames,
			// NOTE: Update [compareBackendParams] if more fields are added here.
		})
	}

	// If there's no addrs in the podInfo, we may need to fall back to the backends
	// we already know about for the underlying service we are redirecting. Build a
	// map of this information indexed by IP address.
	serviceBackendsByAddr := map[cmtypes.AddrCluster][]*lb.Backend{}
	if lrp.LRPType == lrpConfigTypeSvc {
		serviceBackends, _ := lb.ListBackendsByServiceName(wtxn, c.p.Writer.Backends(), lrp.ServiceID)
		preferred := lb.PreferredBackendsByAddress(serviceBackends)
		for be := range preferred {
			addrCluster := be.Address.AddrCluster()
			serviceBackendsByAddr[addrCluster] = append(serviceBackendsByAddr[addrCluster], be)
		}
	}

	hasServiceBackendFallback := len(serviceBackendsByAddr) != 0
	for _, podInfo := range pods {
		// We need backend information for every pod. If there are no addresses
		// provided for this pod, we should try fall back to the backend data we
		// have read from StateDB relating to the LRP target service.
		if len(podInfo.addrs) == 0 && hasServiceBackendFallback {
			// We should only use fall-back data if we do not need to match port
			// names. This provides consistency with earlier versions of Cilium.
			if portNameMatches != nil {
				continue
			}
			for _, podIP := range podInfo.ips {
				for _, be := range serviceBackendsByAddr[podIP] {
					appendBackend(*be)
				}
			}
			continue
		}

		for _, addr := range podInfo.addrs {
			appendBackend(lb.Backend{
				Address: addr.L3n4Addr,
				State:   lb.BackendStateActive,
				PortNames: func() []string {
					if addr.portName != "" {
						return []string{addr.portName}
					}
					return []string{}
				}(),
			})
		}
	}

	// Validate whether an update is actually needed to avoid no-op changes to the tables.
	newCount := len(beps)
	orphanCount := 0
	lrpServiceName := lrp.RedirectServiceName()
	bes, _ := lb.ListBackendsByServiceName(wtxn, c.p.Writer.Backends(), lrpServiceName)
	preferred := lb.PreferredBackendsByAddress(bes)
	for be := range preferred {
		inst := be
		if slices.ContainsFunc(beps, func(bep lb.Backend) bool {
			return compareBackendParams(inst, &bep)
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
		targetName := lrp.ServiceID
		c.p.Writer.RefreshFrontends(wtxn, targetName)
	}
}

func shouldRedirectFrontend(log *slog.Logger, lrp *LocalRedirectPolicy, fe *lb.Frontend, pods []podInfo) bool {
	// 0. Don't redirect if we have no matching target pods.
	if len(pods) == 0 {
		return false
	}

	// 1. First match the frontend based on "RedirectFrontend.ToPorts"
	// 1.1. All frontends match only when no ports were specified in redirectFrontend.
	match := lrp.FrontendType == svcFrontendAll

	// 1.2. Frontend matches if the port number matches
	if !match {
		for _, feM := range lrp.FrontendMappings {
			match = feM.feAddr.Port() == fe.Address.Port() && feM.feAddr.Protocol() == fe.Address.Protocol()
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

	// 2.2. Frontend matches if there is a single frontend port, which filters multiple backend
	// ports. The mapping will be made to the first backend entry, ignoring name. Note that the
	// protocol has already been validated in the LRP parser, but we check it again here
	// for safety.
	if !match {
		match = len(lrp.FrontendMappings) == 1 &&
			lrp.FrontendMappings[0].feAddr.Protocol() == lrp.BackendPorts[0].l4Addr.Protocol
	}

	// 2.3. Frontend matches if there is a backend whose port name matches.
	if !match && lrp.requiresPortNameMatch() {
		_, match = lrp.BackendPortsByPortName[fe.PortName]

		// The port must also be present in at least one pod to be viable for redirect.
		// While the check itself is on portName, we verify protocols and address families
		// too, to ensure we don't redirect across boundaries.
		//
		// TODO: This may perform poorly with a large range of pods. Perhaps it would be
		// better to proactively map enabled ports and protocols when podInfo is being
		// constructed, that way this linear search could be replaced with a lookup.
		if match {
			podIncludesBackendPort := func(pod *podInfo) bool {
				return slices.ContainsFunc(pod.addrs, func(addr podAddr) bool {
					return addr.Compatible(fe.Address) &&
						addr.portName == string(fe.PortName)
				})
			}
			for _, pod := range pods {
				match = podIncludesBackendPort(&pod)
				if match {
					break
				}
			}
		}
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

			toName := lrp.RedirectServiceName()
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
		targetName = lrp.RedirectServiceName()
	} else {
		targetName = lrp.ServiceID
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

func podAddrs(pod *slim_corev1.Pod) (ips []cmtypes.AddrCluster, addrs []podAddr) {
	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) == 0 {
		// IPs not available yet.
		return nil, nil
	}
	for _, podIP := range podIPs {
		addrCluster, err := cmtypes.ParseAddrCluster(podIP)
		if err != nil {
			continue
		}
		ips = append(ips, addrCluster)
	}
	for _, addrCluster := range ips {
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				l4addr := lb.NewL4Addr(lb.L4Type(port.Protocol), uint16(port.ContainerPort))
				addr := podAddr{
					L3n4Addr: lb.NewL3n4Addr(
						l4addr.Protocol,
						addrCluster,
						l4addr.Port,
						lb.ScopeExternal,
					),
					portName: port.Name,
				}
				addrs = append(addrs, addr)
			}
		}
	}
	return ips, addrs
}

// podInfo is the condensed data from the pod relevant for the LRP processing.
type podInfo struct {
	namespace      string
	namespacedName string
	// ips identify the selected pod independently of declared container
	// ports. ServiceMatcher LRPs use these to match selected pods back to
	// reflected service backends when the pod spec does not declare ports.
	ips []cmtypes.AddrCluster
	// addrs are the concrete backend addresses derived from the pod spec.
	// Address-based LRPs rely on these directly, and ServiceMatcher LRPs use
	// them when container ports are declared.
	addrs  []podAddr
	labels map[string]string
}

func getPodInfo(pod k8sTables.LocalPod) podInfo {
	ips, addrs := podAddrs(pod.Pod)
	return podInfo{
		namespace:      pod.Namespace,
		namespacedName: pod.Namespace + "/" + pod.Name,
		ips:            ips,
		addrs:          addrs,
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
