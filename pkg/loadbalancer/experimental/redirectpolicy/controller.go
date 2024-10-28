// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
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

	Enabled lrpIsEnabled
	Log     *slog.Logger
	DB      *statedb.DB
	LRPs    statedb.Table[*LocalRedirectPolicy]
	Pods    statedb.Table[daemonk8s.LocalPod]
	Writer  *experimental.Writer
}

type lrpController struct {
	p lrpControllerParams
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

func (h *lrpController) run(ctx context.Context, health cell.Health) error {
	//
	// Start tracking upserts and deletions of LRPs, Pods and Frontends.
	//

	wtxn := h.p.DB.WriteTxn(h.p.LRPs, h.p.Pods, h.p.Writer.Frontends())
	defer wtxn.Abort()

	lrps, err := h.p.LRPs.Changes(wtxn)
	if err != nil {
		return err
	}

	pods, err := h.p.Pods.Changes(wtxn)
	if err != nil {
		return err
	}

	frontends, err := h.p.Writer.Frontends().Changes(wtxn)
	if err != nil {
		return err
	}
	wtxn.Commit()

	// Limit the rate at which the changes are processed. This allows processing in
	// larger batches and skipping intermediate states of the objects.
	var limiter = rate.NewLimiter(100*time.Millisecond, 1)

	for {
		health.OK("Processing changes")

		wtxn := h.p.Writer.WriteTxn()

		lrpChanges, lrpWatch := lrps.Next(wtxn)
		// Process the changed local redirect policies. Find frontends that should be redirected
		// and find mathed pods from which to create backends.
		for change := range lrpChanges {
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

			switch lrp.lrpType {
			case lrpConfigTypeSvc:
				targetName := lb.ServiceName{Name: lrp.serviceID.Name, Namespace: lrp.serviceID.Namespace}
				if !change.Deleted {
					h.p.Writer.SetRedirectToByName(wtxn, targetName, &toName)
				} else {
					h.p.Writer.SetRedirectToByName(wtxn, targetName, nil)
				}
			case lrpConfigTypeAddr:
				for _, feM := range lrp.frontendMappings {
					if !change.Deleted {
						h.p.Writer.SetRedirectToByAddress(wtxn, feM.feAddr, &toName)
					} else {
						h.p.Writer.SetRedirectToByAddress(wtxn, feM.feAddr, nil)
					}
				}
			}

			// Find pods that match with the LRP
			if !change.Deleted {
				matchingPods := h.p.Pods.Prefix(wtxn, daemonk8s.PodByName(lrp.id.Namespace, ""))
				for pod := range matchingPods {
					if len(pod.Namespace) != len(lrp.id.Namespace) {
						break
					}
					if lrp.backendSelector.Matches(labels.Set(pod.Labels)) {
						h.processLRPAndPod(wtxn, lrp, getPodInfo(pod))
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
			matchingLRPs := h.p.LRPs.Prefix(wtxn, lrpIDIndex.Query(k8s.ServiceID{Namespace: podInfo.namespace}))
			for lrp := range matchingLRPs {
				if len(lrp.id.Namespace) != len(podInfo.namespace) {
					// Different (longer) namespace, stop here.
					break
				}
				if lrp.backendSelector.Matches(labels.Set(podInfo.labels)) {
					if change.Deleted {
						toName := lrp.ServiceName()
						for _, addr := range podInfo.addrs {
							h.p.Writer.ReleaseBackend(wtxn, toName, addr.L3n4Addr)
						}
					} else {
						h.processLRPAndPod(wtxn, lrp, podInfo)
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

			lrp, _, found := h.p.LRPs.Get(wtxn, lrpServiceIndex.Query(serviceID))
			if !found {
				lrp, _, found = h.p.LRPs.Get(wtxn, lrpAddressIndex.Query(fe.Address))
			}
			if !found {
				continue
			}

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

		select {
		case <-lrpWatch:
		case <-podWatch:
		case <-frontendWatch:
		case <-ctx.Done():
			return nil
		}

	}
}

func (h *lrpController) processLRPAndPod(wtxn experimental.WriteTxn, lrp *LocalRedirectPolicy, podInfo podInfo) {
	h.p.Log.Info("processLRPAndPod",
		"lrp", lrp.id,
		"pod", podInfo.namespacedName)

	portNameMatches := func(portName string) bool {
		for bePortName := range lrp.backendPortsByPortName {
			if bePortName == portName {
				return true
			}
		}
		return false
	}

	// Port name checks can be skipped in certain cases.
	switch {
	case lrp.frontendType == svcFrontendAll:
		fallthrough
	case lrp.frontendType == svcFrontendSinglePort:
		fallthrough
	case lrp.frontendType == addrFrontendSinglePort:
		portNameMatches = nil

	}

	toName := lrp.ServiceName()

	for _, addr := range podInfo.addrs {
		if portNameMatches != nil && !portNameMatches(addr.portName) {
			h.p.Log.Info("Mismatching port name", "portName", addr.portName, "frontendType", lrp.frontendType)
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
	switch lrp.lrpType {
	case lrpConfigTypeSvc:
		targetName := lb.ServiceName{Name: lrp.serviceID.Name, Namespace: lrp.serviceID.Namespace}
		h.p.Writer.RefreshFrontends(wtxn, targetName)
	case lrpConfigTypeAddr:
		for _, feM := range lrp.frontendMappings {
			h.p.Writer.RefreshFrontendByAddress(wtxn, feM.feAddr)
		}
	}
}

func (lrp *LocalRedirectPolicy) ServiceName() lb.ServiceName {
	return lb.ServiceName{Name: lrp.id.Name + localRedirectSvcStr, Namespace: lrp.id.Namespace}
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
	g.Add(job.OneShot("controller", h.run))
}
