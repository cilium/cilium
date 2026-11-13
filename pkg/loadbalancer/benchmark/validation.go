// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark

import (
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	lrpTypes "github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy/types"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/source"
)

// validateServiceMatcherLRPs verifies that the generated and parsed policies
// retain the matcher structure needed to exercise the named-port pod scan.
func validateServiceMatcherLRPs(
	db *statedb.DB,
	lrps statedb.Table[*redirectpolicy.LocalRedirectPolicy],
	objects *benchmarkObjectSet,
) error {
	txn := db.ReadTxn()
	if got, want := lrps.NumObjects(txn), len(objects.lrps); got != want {
		return fmt.Errorf("incorrect policy count, got %d, want %d", got, want)
	}

	services := make(map[loadbalancer.ServiceName]*slim_corev1.Service, len(objects.services))
	for _, svc := range objects.services {
		services[loadbalancer.NewServiceName(svc.Namespace, svc.Name)] = svc
	}

	expectedServices := make(map[loadbalancer.ServiceName]loadbalancer.ServiceName, len(objects.lrps))
	wantBackendPorts := []string{"53/UDP (dns)", "53/TCP (dns-tcp)"}
	for _, lrp := range objects.lrps {
		id := loadbalancer.NewServiceName(lrp.Namespace, lrp.Name)
		matcher := lrp.Spec.RedirectFrontend.ServiceMatcher
		if matcher == nil {
			return fmt.Errorf("policy %s does not use a service matcher", id)
		}
		if len(matcher.ToPorts) != 0 {
			return fmt.Errorf("policy %s filters frontend ports, want all service ports", id)
		}
		serviceID := loadbalancer.NewServiceName(matcher.Namespace, matcher.Name)
		svc, found := services[serviceID]
		if !found {
			return fmt.Errorf("policy %s targets unexpected service %s", id, serviceID)
		}
		if !maps.Equal(lrp.Spec.RedirectBackend.LocalEndpointSelector.MatchLabels, svc.Spec.Selector) {
			return fmt.Errorf("policy %s backend selector does not match service %s selector", id, serviceID)
		}
		gotBackendPorts := lrp.Spec.RedirectBackend.ToPorts
		if len(gotBackendPorts) != len(wantBackendPorts) {
			return fmt.Errorf("policy %s has %d backend ports, want %d", id, len(gotBackendPorts), len(wantBackendPorts))
		}
		for i, port := range gotBackendPorts {
			got := fmt.Sprintf("%s/%s (%s)", port.Port, port.Protocol, port.Name)
			if got != wantBackendPorts[i] {
				return fmt.Errorf("policy %s backend port %d is %s, want %s", id, i, got, wantBackendPorts[i])
			}
		}
		expectedServices[id] = serviceID
	}

	for lrp := range lrps.All(txn) {
		wantService, found := expectedServices[lrp.ID]
		if !found {
			return fmt.Errorf("unexpected policy %s", lrp.ID)
		}
		if lrp.LRPType != lrpTypes.LRPTypeServiceMatcher {
			return fmt.Errorf("policy %s has type %s, want %s", lrp.ID, lrp.LRPType, lrpTypes.LRPTypeServiceMatcher)
		}
		if lrp.FrontendType != lrpTypes.FrontendTypeServiceAll {
			return fmt.Errorf("policy %s has frontend type %s, want %s", lrp.ID, lrp.FrontendType, lrpTypes.FrontendTypeServiceAll)
		}
		if !lrp.ServiceID.Equal(wantService) {
			return fmt.Errorf("policy %s targets service %s, want %s", lrp.ID, lrp.ServiceID, wantService)
		}
		if got, want := len(lrp.BackendPorts), len(wantBackendPorts); got != want {
			return fmt.Errorf("policy %s has %d backend ports, want %d", lrp.ID, got, want)
		}
		for i, port := range lrp.BackendPorts {
			if got, want := port.String(), wantBackendPorts[i]; got != want {
				return fmt.Errorf("policy %s parsed backend port %d is %s, want %s", lrp.ID, i, got, want)
			}
		}
		for _, portName := range []loadbalancer.FEPortName{"dns", "dns-tcp"} {
			if _, found := lrp.BackendPortsByPortName[portName]; !found {
				return fmt.Errorf("policy %s does not contain backend port %q", lrp.ID, portName)
			}
		}
	}
	return nil
}

func checkTables(db *statedb.DB, writer *writer.Writer, objects *benchmarkObjectSet) error {
	txn := db.ReadTxn()
	var err error
	hasServiceMatcherLRPs := len(objects.lrps) > 0
	expectedServices := make(map[loadbalancer.ServiceName]*slim_corev1.Service, len(objects.services))
	expectedEndpoints := make(map[loadbalancer.ServiceName]*k8s.Endpoints, len(objects.endpointSlices))
	for _, svc := range objects.services {
		svcName := loadbalancer.NewServiceName(svc.Namespace, svc.Name)
		expectedServices[svcName] = svc
	}
	for _, ep := range objects.endpointSlices {
		expectedEndpoints[ep.ServiceName] = ep
	}

	expectedServiceCount := len(objects.services)
	if hasServiceMatcherLRPs {
		expectedServiceCount += len(objects.lrps)
	}
	if servicesNo := writer.Services().NumObjects(txn); servicesNo != expectedServiceCount {
		err = errors.Join(err, fmt.Errorf("incorrect number of services, got %d, want %d", servicesNo, expectedServiceCount))
	}
	for svc := range writer.Services().All(txn) {
		if _, found := expectedServices[svc.Name]; !found {
			if _, found := objects.lrpTargets[svc.Name]; !found {
				err = errors.Join(err, fmt.Errorf("unexpected service %s", svc.Name))
			}
		}
		if svc.Source != source.Kubernetes {
			err = errors.Join(err, fmt.Errorf("incorrect source for service %s, got %q, want %q", svc.Name, svc.Source, source.Kubernetes))
		}
		if svc.ExtTrafficPolicy != loadbalancer.SVCTrafficPolicyCluster {
			err = errors.Join(err, fmt.Errorf("incorrect external traffic policy for service %s, got %q, want %q", svc.Name, svc.ExtTrafficPolicy, loadbalancer.SVCTrafficPolicyCluster))
		}
		if svc.IntTrafficPolicy != loadbalancer.SVCTrafficPolicyCluster {
			err = errors.Join(err, fmt.Errorf("incorrect internal traffic policy for service %s, got %q, want %q", svc.Name, svc.IntTrafficPolicy, loadbalancer.SVCTrafficPolicyCluster))
		}
	}

	if frontendsNo := writer.Frontends().NumObjects(txn); frontendsNo != len(objects.services) {
		err = errors.Join(err, fmt.Errorf("incorrect number of frontends, got %d, want %d", frontendsNo, len(objects.services)))
	}
	for fe := range writer.Frontends().All(txn) {
		want, found := expectedServices[fe.ServiceName]
		if !found {
			err = errors.Join(err, fmt.Errorf("unexpected frontend service %s", fe.ServiceName))
			continue
		}
		wantIP, _ := netip.ParseAddr(want.Spec.ClusterIP)
		if fe.Address.Addr() != wantIP {
			err = errors.Join(err, fmt.Errorf("incorrect address for frontend %s, got %v, want %v", fe.ServiceName, fe.Address.Addr(), wantIP))
		}
		if fe.Type != loadbalancer.SVCType(want.Spec.Type) {
			err = errors.Join(err, fmt.Errorf("incorrect service type for frontend %s, got %v, want %v", fe.ServiceName, fe.Type, loadbalancer.SVCType(want.Spec.Type)))
		}
		if fe.PortName != loadbalancer.FEPortName(want.Spec.Ports[0].Name) {
			err = errors.Join(err, fmt.Errorf("incorrect port name for frontend %s, got %v, want %v", fe.ServiceName, fe.PortName, loadbalancer.FEPortName(want.Spec.Ports[0].Name)))
		}
		if fe.Status.Kind != reconciler.StatusKindDone {
			err = errors.Join(err, fmt.Errorf("incorrect status for frontend %s, got %v, want Done", fe.ServiceName, fe.Status.Kind))
		}
		backends := slices.Collect(statedb.ToSeq(iter.Seq2[*loadbalancer.Backend, statedb.Revision](fe.Backends)))
		if wantRedirect, shouldRedirect := objects.lrpServices[fe.ServiceName]; shouldRedirect {
			if fe.RedirectTo == nil {
				err = errors.Join(err, fmt.Errorf("frontend %s was not redirected", fe.ServiceName))
			} else if !fe.RedirectTo.Equal(wantRedirect) {
				err = errors.Join(err, fmt.Errorf("frontend %s redirected to %s, want %s", fe.ServiceName, fe.RedirectTo, wantRedirect))
			}
			if len(backends) != 1 {
				err = errors.Join(err, fmt.Errorf("incorrect redirected backend count for frontend %s, got %d, want 1", fe.ServiceName, len(backends)))
			} else {
				wantBackendIP := objects.lrpBackendLastIP[wantRedirect]
				backend := backends[0]
				if !backend.ServiceName.Equal(wantRedirect) {
					err = errors.Join(err, fmt.Errorf("frontend %s selected backend from %s, want %s", fe.ServiceName, backend.ServiceName, wantRedirect))
				}
				if backend.Address.Addr() != wantBackendIP || backend.Address.Port() != 53 || backend.Address.Protocol() != loadbalancer.TCP {
					err = errors.Join(err, fmt.Errorf("frontend %s selected backend %s, want %s:53/TCP", fe.ServiceName, backend.Address, wantBackendIP))
				}
				if !slices.Contains(backend.PortNames, "dns-tcp") {
					err = errors.Join(err, fmt.Errorf("frontend %s selected backend %s without port name dns-tcp", fe.ServiceName, backend.Address))
				}
			}
		} else {
			if fe.RedirectTo != nil {
				err = errors.Join(err, fmt.Errorf("frontend %s was unexpectedly redirected to %s", fe.ServiceName, fe.RedirectTo))
			}
			wantEndpoints := expectedEndpoints[fe.ServiceName]
			if len(backends) != len(wantEndpoints.Backends) {
				err = errors.Join(err, fmt.Errorf("incorrect backend count for frontend %s, got %d, want %d", fe.ServiceName, len(backends), len(wantEndpoints.Backends)))
			}
		}
	}

	if backendsNo := writer.Backends().NumObjects(txn); backendsNo != objects.backendCount {
		err = errors.Join(err, fmt.Errorf("incorrect number of backends, got %d, want %d", backendsNo, objects.backendCount))
	}
	lrpBackendCounts := make(map[loadbalancer.ServiceName]int, len(objects.lrpTargets))
	for be := range writer.Backends().All(txn) {
		want, found := expectedEndpoints[be.ServiceName]
		if !found {
			if _, found := objects.lrpTargets[be.ServiceName]; !found {
				err = errors.Join(err, fmt.Errorf("unexpected backend service %s", be.ServiceName))
			} else {
				lrpBackendCounts[be.ServiceName]++
				if !isExpectedLRPBackend(be, objects.lrpBackendIPs[be.ServiceName], objects.lrpBackendLastIP[be.ServiceName]) {
					err = errors.Join(err, fmt.Errorf("unexpected local redirect backend %s for service %s", be.Address, be.ServiceName))
				}
			}
		} else {
			wantBackend, found := want.Backends[be.Address.AddrCluster()]
			if !found {
				err = errors.Join(err, fmt.Errorf("unexpected backend address %s for service %s", be.Address, be.ServiceName))
				continue
			}
			portFound := false
			for wantPort := range wantBackend.Ports {
				portFound = portFound || (be.Address.Port() == wantPort.Port && be.Address.Protocol() == wantPort.Protocol)
			}
			if !portFound {
				err = errors.Join(err, fmt.Errorf("unexpected backend port %s for service %s", be.Address, be.ServiceName))
			}
		}
		if state, stateErr := be.State.String(); stateErr != nil || state != "active" {
			err = errors.Join(err, fmt.Errorf("incorrect state for backend %s, got %q, want active", be.Address, state))
		}
	}
	for svcName := range objects.lrpTargets {
		want := objects.lrpBackendCounts[svcName]
		if got := lrpBackendCounts[svcName]; got != want {
			err = errors.Join(err, fmt.Errorf("incorrect local redirect backend count for service %s, got %d, want %d", svcName, got, want))
		}
	}

	return err
}

func isExpectedLRPBackend(be *loadbalancer.Backend, expectedIPs map[netip.Addr]struct{}, lastBackendIP netip.Addr) bool {
	if _, found := expectedIPs[be.Address.Addr()]; !found {
		return false
	}

	// Each exposed pod port produces a separate backend. Every generated pod,
	// including the final one, contributes a dns UDP/53 backend.
	if slices.Contains(be.PortNames, "dns") {
		return be.Address.Port() == 53 && be.Address.Protocol() == loadbalancer.UDP
	}

	// Only the final generated pod contributes a dns-tcp TCP/53 backend.
	return be.Address.Addr() == lastBackendIP &&
		slices.Contains(be.PortNames, "dns-tcp") &&
		be.Address.Port() == 53 &&
		be.Address.Protocol() == loadbalancer.TCP
}

func fastCheckTables(db *statedb.DB, writer *writer.Writer, expectedFrontends, expectedRedirects int, lastPendingRevision statedb.Revision) (reconciled bool, nextRevision statedb.Revision) {
	txn := db.ReadTxn()
	if writer.Frontends().NumObjects(txn) < expectedFrontends {
		return false, 0
	}
	var rev uint64
	var fe *loadbalancer.Frontend
	for fe, rev = range writer.Frontends().LowerBound(txn, statedb.ByRevision[*loadbalancer.Frontend](lastPendingRevision)) {
		if fe.Status.Kind != reconciler.StatusKindDone {
			return false, rev
		}
	}
	redirects := 0
	for fe := range writer.Frontends().All(txn) {
		if fe.RedirectTo != nil {
			redirects++
		}
	}
	if redirects != expectedRedirects {
		return false, rev
	}
	return true, rev
}

func fastCheckEmptyTablesAndState(
	db *statedb.DB,
	writer *writer.Writer,
	bo *lbreconciler.BPFOps,
	pods statedb.Table[k8sTables.LocalPod],
	lrps statedb.Table[*redirectpolicy.LocalRedirectPolicy],
) bool {
	txn := db.ReadTxn()
	if writer.Frontends().NumObjects(txn) > 0 || writer.Backends().NumObjects(txn) > 0 || writer.Services().NumObjects(txn) > 0 {
		return false
	}
	if pods != nil && pods.NumObjects(txn) > 0 {
		return false
	}
	if lrps != nil && lrps.NumObjects(txn) > 0 {
		return false
	}
	return bo.StateIsEmpty()
}
