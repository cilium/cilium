// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var experimentalCell = cell.Module(
	"local-redirect-policies",
	"Controller for CiliumLocalRedirectPolicy",

	experimentalCells,
	cell.ProvidePrivate(
		newPodListerWatcher,
		newLRPListerWatcher,
		newLRPIsEnabled,
	),
)

type lrpIsEnabled bool

func newLRPIsEnabled(expConfig experimental.Config, daemonConfig *option.DaemonConfig) lrpIsEnabled {
	return lrpIsEnabled(
		expConfig.EnableExperimentalLB && daemonConfig.EnableLocalRedirectPolicy,
	)
}

var experimentalCells = cell.Group(
	cell.ProvidePrivate(
		NewLRPTable,
		statedb.RWTable[*LRPConfig].ToTable,

		NewPodTable, // FIXME the pod table should replace Resource[Pod] and be supplied from e.g. daemon/k8s.
		k8s.OnDemandTable[LocalPod],
	),

	cell.Invoke(
		registerLRPReflector,
		registerLRPController,
	),

	cell.ProvidePrivate(
		podReflectorConfig,
	),
)

type lrpControllerParams struct {
	cell.In

	Enabled lrpIsEnabled
	Log     *slog.Logger
	DB      *statedb.DB
	LRPs    statedb.Table[*LRPConfig]
	PodsOD  hive.OnDemand[statedb.Table[LocalPod]]
	Writer  *experimental.Writer
}

type lrpController struct {
	p lrpControllerParams
}

func (h *lrpController) reconciler(ctx context.Context, health cell.Health) error {
	podsTable, err := h.p.PodsOD.Acquire(ctx)
	if err != nil {
		return err
	}
	defer h.p.PodsOD.Release(podsTable)

	//
	// Start tracking upserts and deletions of LRPs, Pods and Frontends.
	//

	wtxn := h.p.DB.WriteTxn(h.p.LRPs, podsTable, h.p.Writer.Frontends())
	defer wtxn.Abort()

	lrps, err := h.p.LRPs.Changes(wtxn)
	if err != nil {
		return err
	}
	defer lrps.Close()

	pods, err := podsTable.Changes(wtxn)
	if err != nil {
		return err
	}
	defer pods.Close()

	frontends, err := h.p.Writer.Frontends().Changes(wtxn)
	if err != nil {
		return err
	}
	defer frontends.Close()
	wtxn.Commit()

	// Limit the rate at which the changes are processed. This allows processing in
	// larger batches and skipping intermediate states of the objects.
	var limiter = rate.NewLimiter(100*time.Millisecond, 1)

	for {
		health.OK("Processing changes")

		wtxn := h.p.Writer.WriteTxn()
		watchLRPs := lrps.Watch(wtxn)

		// Process the changed local redirect policies. Find frontends that should be redirected
		// and find mathed pods from which to create backends.
		for change, _, ok := lrps.Next(); ok; change, _, ok = lrps.Next() {
			lrp := change.Object
			toName := lrp.ServiceName()

			if change.Deleted {
				h.p.Writer.DeleteServiceAndFrontends(wtxn, toName)
			} else {
				// Create a frontendless pseudo-service for the redirect policy. The backends
				// will be associated with this service.
				h.p.Writer.UpsertService(wtxn,
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
					h.p.Writer.SetRedirectToByName(wtxn, targetName, &toName)
				} else {
					h.p.Writer.SetRedirectToByName(wtxn, targetName, nil)
				}
			case lrpConfigTypeAddr:
				// TODO: named ports?
				for _, feM := range lrp.FrontendMappings {
					if !change.Deleted {
						h.p.Writer.SetRedirectToByAddress(wtxn, *feM.FEAddr, &toName)
					} else {
						h.p.Writer.SetRedirectToByAddress(wtxn, *feM.FEAddr, nil)
					}
				}
			}

			// Find pods that match with the LRP
			if !change.Deleted {
				iter := podsTable.Prefix(wtxn, PodNameIndex.Query(lrp.ID.Namespace))
				for pod, _, ok := iter.Next(); ok; pod, _, ok = iter.Next() {
					if len(pod.Namespace) != len(lrp.ID.Namespace) {
						break
					}
					if lrp.BackendSelector.Matches(pod.LabelSet) {
						h.processLRPAndPod(wtxn, lrp, pod)
					}
				}
			}
		}

		watchPods := pods.Watch(wtxn)

		// Process changed pods and find matching LRPs and add the pods as backends.
		for change, _, ok := pods.Next(); ok; change, _, ok = pods.Next() {
			// TODO: Avoid repeated work when there are unrelated changes to the pod.
			// e.g. we just care about changes to the L3n4Addrs and labels.

			pod := change.Object

			// Find LRPs in the same namespace that match with this pod.
			iter := h.p.LRPs.Prefix(wtxn, lrpIDIndex.Query(k8s.ServiceID{Namespace: pod.Namespace}))
			for lrp, _, ok := iter.Next(); ok; lrp, _, ok = iter.Next() {
				if len(lrp.ID.Namespace) != len(pod.Namespace) {
					// Different (longer) namespace, stop here.
					break
				}
				if lrp.BackendSelector.Matches(pod.LabelSet) {
					if change.Deleted {
						toName := lrp.ServiceName()
						for _, addr := range pod.L3n4Addrs {
							h.p.Writer.ReleaseBackend(wtxn, toName, addr.L3n4Addr)
						}
					} else {
						if k8sUtils.GetLatestPodReadiness(pod.Status) != slim_corev1.ConditionTrue {
							continue
						}
						if lrp.BackendSelector.Matches(pod.LabelSet) {
							h.processLRPAndPod(wtxn, lrp, pod)
						}
					}
				}
			}
		}

		watchFrontends := frontends.Watch(wtxn)

		for change, _, ok := frontends.Next(); ok; change, _, ok = frontends.Next() {
			fe := change.Object
			if change.Deleted {
				continue
			}

			serviceID := k8s.ServiceID{
				Namespace: fe.ServiceName.Namespace,
				Name:      fe.ServiceName.Name,
			}

			lrp, _, found := h.p.LRPs.Get(wtxn, lrpServiceIndex.Query(serviceID))
			if !found {
				lrp, _, found = h.p.LRPs.Get(wtxn, lrpAddressIndex.Query(fe.Address))
			}
			if !found {
				continue
			}

			// FIXME port name matching against frontendMappings.

			// A local redirect policy matches this frontend, set the redirect.
			toName := lrp.ServiceName()
			h.p.Writer.SetRedirectToByAddress(wtxn, fe.Address, &toName)
		}

		wtxn.Commit()

		health.OK("Waiting for changes")

		// Rate limit the processing of the changes to increase efficiency.
		if err := limiter.Wait(ctx); err != nil {
			// Context cancelled, shutting down.
			return nil
		}

		// Refresh and wait for more changes.
		select {
		case <-watchLRPs:
		case <-watchPods:
		case <-watchFrontends:
		case <-ctx.Done():
			return nil
		}

	}
}

func (h *lrpController) processLRPAndPod(wtxn experimental.WriteTxn, lrp *LRPConfig, pod LocalPod) {
	h.p.Log.Info("processLRPAndPod",
		"lrp", lrp.ID,
		"pod", pod.Name)

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

	for _, addr := range pod.L3n4Addrs {
		if portNameMatches != nil && !portNameMatches(addr.portName) {
			h.p.Log.Info("Mismatching port name", "portName", addr.portName, "frontendType", lrp.FrontendType)
			continue
		}
		be := experimental.BackendParams{
			L3n4Addr: addr.L3n4Addr,
			State:    lb.BackendStateActive,
			PortName: addr.portName,
		}
		h.p.Log.Info("Adding backend instance", "name", toName)
		h.p.Writer.UpsertBackends(
			wtxn,
			toName,
			source.Kubernetes,
			be,
		)
	}

	// Finally refresh the frontends to recalculate their backends.
	switch lrp.LRPType {
	case lrpConfigTypeSvc:
		targetName := lb.ServiceName{Name: lrp.ServiceID.Name, Namespace: lrp.ServiceID.Namespace}
		h.p.Writer.RefreshFrontends(wtxn, targetName)
	case lrpConfigTypeAddr:
		for _, feM := range lrp.FrontendMappings {
			h.p.Writer.RefreshFrontendByAddress(wtxn, *feM.FEAddr)
		}
	}
}

func (lrp *LRPConfig) ServiceName() lb.ServiceName {
	return lb.ServiceName{Name: lrp.ID.Name + localRedirectSvcStr, Namespace: lrp.ID.Namespace}
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
				if port.Name == "" {
					continue
				}
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
	h := &lrpController{p}
	g.Add(job.OneShot("reconciler", h.reconciler))
}

func (lrp *LRPConfig) TableHeader() []string {
	return []string{
		"ID",
		"Type",
		"FrontendType",
		"Mappings",
	}
}
func (lrp *LRPConfig) TableRow() []string {
	m := lrp.GetModel()
	mappings := make([]string, 0, len(m.FrontendMappings))
	for _, feM := range m.FrontendMappings {
		addr := feM.FrontendAddress
		mappings = append(mappings,
			fmt.Sprintf("%s:%d %s", addr.IP, addr.Port, addr.Protocol))
	}
	return []string{
		m.Namespace + "/" + m.Name,
		m.LrpType,
		m.FrontendType,
		strings.Join(mappings, ", "),
	}

}
