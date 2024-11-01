// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

// Convenient aliases for the service types.
const (
	HostPort      = loadbalancer.SVCTypeHostPort
	ClusterIP     = loadbalancer.SVCTypeClusterIP
	NodePort      = loadbalancer.SVCTypeNodePort
	ExternalIPs   = loadbalancer.SVCTypeExternalIPs
	LoadBalancer  = loadbalancer.SVCTypeLoadBalancer
	LocalRedirect = loadbalancer.SVCTypeLocalRedirect
)

type testCase struct {
	name string

	// frontend and the associated service + backends.
	frontend Frontend

	delete bool

	// maps are the dumped BPF maps. These should not be hand-written but rather
	// pasted in from the failing test case when a new test-case is added.
	// Sorted.
	maps []MapDump
}

var testServiceName = loadbalancer.ServiceName{Name: "test", Namespace: "test"}

var baseService = Service{
	Name:                   testServiceName,
	Source:                 source.Kubernetes,
	Labels:                 nil,
	NatPolicy:              loadbalancer.SVCNatPolicyNone,
	ExtTrafficPolicy:       loadbalancer.SVCTrafficPolicyLocal,
	IntTrafficPolicy:       loadbalancer.SVCTrafficPolicyLocal,
	SessionAffinity:        false,
	SessionAffinityTimeout: 0,
	L7ProxyPort:            0,
	LoopbackHostPort:       false,
}

var baseFrontend = Frontend{
	FrontendParams: FrontendParams{
		ServiceName: testServiceName,
		PortName:    "", // Ignored, backends already resolved.
	},
	Status:        reconciler.StatusPending(),
	nodePortAddrs: nodePortAddrs,
}

var emptyInstances part.Map[loadbalancer.ServiceName, BackendInstance]

var baseBackend = Backend{
	L3n4Addr: backend1,
	NodeName: "",
	ZoneID:   0,
	Instances: emptyInstances.Set(
		testServiceName,
		BackendInstance{
			PortName: "",
			Weight:   0,
			State:    loadbalancer.BackendStateActive,
		},
	),
}

var nextBackendRevision = statedb.Revision(1)

// newTestCase creates a testCase from a function that manipulates the base service and frontends.
func newTestCase(name string, mod func(*Service, *Frontend) (delete bool, bes []Backend), maps []MapDump) testCase {
	svc := baseService
	fe := baseFrontend
	delete, bes := mod(&svc, &fe)
	fe.service = &svc
	for _, be := range bes {
		fe.Backends = append(fe.Backends, BackendWithRevision{Backend: &be, Revision: nextBackendRevision})
		nextBackendRevision++
	}
	return testCase{
		name:     name,
		frontend: fe,
		delete:   delete,
		maps:     maps,
	}
}

func deleteFrontend(addr loadbalancer.L3n4Addr, typ loadbalancer.SVCType) func(*Service, *Frontend) (bool, []Backend) {
	return func(svc *Service, fe *Frontend) (bool, []Backend) {
		fe.Type = typ
		fe.Address = addr
		return true, nil
	}
}

// clusterIPTestCases test the ClusterIP type and the backend handling that's common for all
// service types.
var clusterIPTestCases = []testCase{
	newTestCase(
		"ClusterIP_no_backends",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, nil
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"ClusterIP_1_backend",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, []Backend{baseBackend}
		},
		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"ClusterIP_2_backends",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2 := baseBackend, baseBackend
			be1.L3n4Addr = backend1
			be2.L3n4Addr = backend2
			return false, []Backend{be1, be2}
		},
		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80 STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=2 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"ClusterIP_delete_backends",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, nil
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	// Test that adding another frontend allocates new IDs correctly.
	newTestCase(
		"ClusterIP_extra_frontend",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = extraFrontend
			return false, nil
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=10.0.0.2:80 SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"ClusterIP_delete_extra",
		deleteFrontend(extraFrontend, ClusterIP),
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	// Adding the same frontend again won't reuse the ID as it should have been released.
	newTestCase(
		"ClusterIP_extra_frontend_again",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = extraFrontend
			return false, nil
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"REV: ID=3 ADDR=10.0.0.2:80",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=3 ADDR=10.0.0.2:80 SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"ClusterIP_delete_extra_again",
		deleteFrontend(extraFrontend, ClusterIP),
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"ClusterIP_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]MapDump{},
	),
}

var quarantineTestCases = []testCase{
	newTestCase(
		"Quarantine_2_active_backends",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2 := baseBackend, baseBackend
			be1.L3n4Addr = backend1
			be2.L3n4Addr = backend2
			return false, []Backend{be1, be2}
		},
		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80 STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=2 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"Quarantine_1_active_1_quarantined",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2 := baseBackend, baseBackend
			be1.L3n4Addr = backend1
			be2.L3n4Addr = backend2
			be1.State = loadbalancer.BackendStateQuarantined
			return false, []Backend{be1, be2}
		},
		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=quarantined",
			"BE: ID=2 ADDR=10.1.0.2:80 STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=1 QCOUNT=1 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto> SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"Quarantine_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]MapDump{},
	),
}

var nodePortTestCases = []testCase{
	newTestCase(
		"NodePort",

		// For NodePort we only create the surrogate entry with zero IP
		// address. From this additional services map entries are created
		// for each node IP address.

		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			be1, be2 := baseBackend, baseBackend
			be1.L3n4Addr = backend1
			be2.L3n4Addr = backend2
			return false, []Backend{be1, be2}
		},

		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80 STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero> SLOT=0 BEID=0 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=<nodePort> SLOT=0 BEID=0 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
			"SVC: ID=2 ADDR=<nodePort> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
			"SVC: ID=2 ADDR=<nodePort> SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
		},
	),

	newTestCase(
		"NodePort_cleanup",
		deleteFrontend(zeroAddr, NodePort),
		[]MapDump{},
	),
}

var hostPortTestCases = []testCase{
	// HostPort. Essentially same as NodePort when zero address is used,
	// e.g. there's a service frontend for each Node IP address.
	newTestCase(
		"HostPort_zero",

		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = HostPort
			fe.Address = zeroAddr
			return false, []Backend{baseBackend}
		},
		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=<nodePort> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
			"SVC: ID=2 ADDR=<nodePort> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
	),

	newTestCase(
		"HostPort_zero_cleanup",
		deleteFrontend(zeroAddr, HostPort),
		[]MapDump{},
	),

	// HostPort with fixed address.
	newTestCase(
		"HostPort_fixed",

		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = HostPort
			fe.Address = autoAddr
			return false, []Backend{baseBackend}
		},
		[]MapDump{
			"BE: ID=2 ADDR=10.1.0.1:80 STATE=active",
			"REV: ID=3 ADDR=<auto>",
			"SVC: ID=3 ADDR=<auto> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
			"SVC: ID=3 ADDR=<auto> SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
	),

	newTestCase(
		"HostPort_fixed_cleanup",
		deleteFrontend(autoAddr, HostPort),
		[]MapDump{},
	),
}

var proxyTestCases = []testCase{
	newTestCase(
		"L7Proxy",

		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr

			// The port is stored as the backend ID in network byte-order, which is different
			// from how the backend ID is normally stored (host byte-order). Hence to make this
			// work on both little and big-endian machine's the port is set to a value that's the
			// same in both byte orders.
			svc.L7ProxyPort = 0x0a0a // 2570
			return false, []Backend{baseBackend}
		},
		[]MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=2570 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+l7-load-balancer",
			"SVC: ID=1 ADDR=<auto> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+l7-load-balancer",
		},
	),
	newTestCase(
		"L7Proxy_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]MapDump{},
	),
}

var extraFrontendInternal = func() loadbalancer.L3n4Addr {
	addr := extraFrontend
	addr.Scope = loadbalancer.ScopeInternal
	return addr
}()

var miscFlagsTestCases = []testCase{
	newTestCase(
		"MiscFlags_Nat46x64",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			svc.NatPolicy = loadbalancer.SVCNatPolicyNat46
			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+46x64",
		},
	),

	newTestCase(
		"MiscFlags_Ext_Cluster",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			svc.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+InternalLocal+non-routable",
		},
	),

	newTestCase(
		"MiscFlags_Int_Cluster",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+non-routable",
		},
	),

	newTestCase(
		"MiscFlags_Both_Cluster",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr

			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster

			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+non-routable",
		},
	),

	newTestCase(
		"MiscFlags_cleanup_1",
		deleteFrontend(autoAddr, ClusterIP),
		[]MapDump{},
	),

	newTestCase(
		"MiscFlags_ScopeInternal",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = HostPort
			fe.Address = extraFrontendInternal
			fe.Address.Scope = loadbalancer.ScopeInternal

			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=2 ADDR=10.0.0.2:80/i SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
	),

	newTestCase(
		"MiscFlags_TwoTrafficPolicyScopes",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = HostPort
			fe.Address = extraFrontendInternal
			fe.Address.Scope = loadbalancer.ScopeInternal

			svc.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster

			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=2 ADDR=10.0.0.2:80/i SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+two-scopes",
		},
	),

	newTestCase(
		"MiscFlags_cleanup_2",
		deleteFrontend(extraFrontendInternal, ClusterIP),
		[]MapDump{},
	),
}

var loadBalancerTestCases = []testCase{
	// TODO/NOTE: Current idea is that:
	// the NodePort service for LoadBalancer should be created by the data reflector,
	// e.g. a K8s LoadBalancer service should create one LoadBalancer per loadbalancerIP and one
	// NodePort with zero address.
	// Is this reasonable approach?
	newTestCase(
		"LoadBalancer",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = LoadBalancer
			fe.Address = autoAddr
			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=LoadBalancer+Local+InternalLocal",
		},
	),

	newTestCase(
		"LoadBalancer_cleanup",
		deleteFrontend(autoAddr, LoadBalancer),
		[]MapDump{},
	),
}

var externalIPTestCases = []testCase{
	newTestCase(
		"ExternalIPs",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = ExternalIPs
			fe.Address = autoAddr
			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=ExternalIPs+Local+InternalLocal",
		},
	),

	newTestCase(
		"ExternalIPs_cleanup",
		deleteFrontend(autoAddr, ExternalIPs),
		[]MapDump{},
	),
}

var localRedirectTestCases = []testCase{
	// TODO: The LocalRedirect mechanism needs to be thought through.
	// One option is to implement it the same way as L7 redirect with a boolean
	// field to enable it. Need to figure out how to query for the backends though.
	// Could either play with the "-local" suffix, or just have a boolean in Backend
	// to mark it as the "local redirect backend" and then just filter for these on
	// the fly (if Frontend.LocalRedirect set, take the redirect backends that reference the service,
	// otherwise non-redirect backends).
	newTestCase(
		"LocalRedirect",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = LocalRedirect
			fe.Address = autoAddr
			return false, []Backend{}
		},
		[]MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto> SLOT=0 BEID=0 COUNT=0 QCOUNT=0 FLAGS=LocalRedirect+Local+InternalLocal",
		},
	),

	newTestCase(
		"LocalRedirect_cleanup",
		deleteFrontend(autoAddr, LocalRedirect),
		[]MapDump{},
	),
}

var sessionAffinityTestCases = []testCase{
	newTestCase(
		"SessionAffinity",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = true
			svc.SessionAffinityTimeout = time.Second

			be1, be2 := baseBackend, baseBackend
			be1.L3n4Addr = backend1
			be2.L3n4Addr = backend2
			return false, []Backend{be1, be2}
		},

		[]MapDump{
			"AFF: ID=1 BEID=1",
			"AFF: ID=1 BEID=2",
			"AFF: ID=2 BEID=1",
			"AFF: ID=2 BEID=2",
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80 STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero> SLOT=0 BEID=1 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=<nodePort> SLOT=0 BEID=1 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort> SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort> SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
		},
	),

	newTestCase(
		"SessionAffinity_quarantine",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = true
			svc.SessionAffinityTimeout = time.Second

			be1, be2 := baseBackend, baseBackend
			be1.L3n4Addr = backend1
			be2.L3n4Addr = backend2
			be1.State = loadbalancer.BackendStateQuarantined
			return false, []Backend{be1, be2}
		},

		[]MapDump{
			"AFF: ID=1 BEID=2",
			"AFF: ID=2 BEID=2",
			"BE: ID=1 ADDR=10.1.0.1:80 STATE=quarantined",
			"BE: ID=2 ADDR=10.1.0.2:80 STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero> SLOT=0 BEID=1 COUNT=1 QCOUNT=1 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero> SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=<nodePort> SLOT=0 BEID=1 COUNT=1 QCOUNT=1 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort> SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort> SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
		},
	),
	newTestCase(
		"SessionAffinity_cleanup_1",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			// Even if SessionAffinity was turned off the affinity map should be cleaned.
			svc.SessionAffinity = false
			return true, nil
		},
		[]MapDump{},
	),

	newTestCase(
		"SessionAffinity_add_to_disable",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = true
			return false, []Backend{baseBackend}
		},
		[]MapDump{
			"AFF: ID=3 BEID=3",
			"AFF: ID=4 BEID=3",
			"BE: ID=3 ADDR=10.1.0.1:80 STATE=active",
			"REV: ID=3 ADDR=<zero>",
			"REV: ID=4 ADDR=<nodePort>",
			"SVC: ID=3 ADDR=<zero> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=3 ADDR=<zero> SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=4 ADDR=<nodePort> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=4 ADDR=<nodePort> SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
		},
	),

	// Disable session affinity to verify that the affinity match maps are cleaned up.
	newTestCase(
		"SessionAffinity_disable",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = false
			return false, []Backend{baseBackend}
		},
		[]MapDump{
			"BE: ID=3 ADDR=10.1.0.1:80 STATE=active",
			"REV: ID=3 ADDR=<zero>",
			"REV: ID=4 ADDR=<nodePort>",
			"SVC: ID=3 ADDR=<zero> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=3 ADDR=<zero> SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=4 ADDR=<nodePort> SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
			"SVC: ID=4 ADDR=<nodePort> SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
		},
	),

	newTestCase(
		"SessionAffinity_cleanup_2",
		func(svc *Service, fe *Frontend) (delete bool, bes []Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			// Flip SessionAffinity on again to verify that it doesn't affect the deletion
			// even when this frontend was reconciled without SessionAffinity.
			svc.SessionAffinity = true
			return true, nil
		},
		[]MapDump{},
	),
}

var testCases = [][]testCase{
	clusterIPTestCases,
	quarantineTestCases,
	nodePortTestCases,
	hostPortTestCases,
	proxyTestCases,
	miscFlagsTestCases,
	loadBalancerTestCases,
	externalIPTestCases,
	localRedirectTestCases,
	sessionAffinityTestCases,
}

func TestBPFOps(t *testing.T) {

	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)

	var lbmaps LBMaps
	if testutils.IsPrivileged() {
		r := &BPFLBMaps{
			Pinned: false,
			Cfg: LBMapsConfig{
				MaxSockRevNatMapEntries:  1000,
				ServiceMapMaxEntries:     1000,
				BackendMapMaxEntries:     1000,
				RevNatMapMaxEntries:      1000,
				AffinityMapMaxEntries:    1000,
				SourceRangeMapMaxEntries: 1000,
				MaglevMapMaxEntries:      1000,
			},
		}
		lc.Append(r)
		lbmaps = r
	} else {
		lbmaps = NewFakeLBMaps()
	}

	// Enable features.
	extCfg := externalConfig{
		EnableSessionAffinity: true,
	}

	cfg := DefaultConfig
	cfg.EnableExperimentalLB = true

	for _, testCaseSet := range testCases {
		// Run each set with IPv4 and IPv6 addresses.
		for _, addr := range frontendAddrs {
			// For each set of test cases, use a fresh instance so each set gets
			// fresh IDs.
			ops := newBPFOps(lc, log, cfg, extCfg, lbmaps)
			for _, testCase := range testCaseSet {
				t.Run(testCase.name, func(t *testing.T) {
					frontend := testCase.frontend
					switch frontend.Address.String() {
					case autoAddr.String():
						frontend.Address = addr
					case zeroAddr.String():
						frontend.Address.L4Addr = addr.L4Addr
						if addr.IsIPv6() {
							frontend.Address.AddrCluster = types.AddrClusterFrom(netip.IPv6Unspecified(), 0)
						} else {
							frontend.Address.AddrCluster = types.AddrClusterFrom(netip.IPv4Unspecified(), 0)
						}
					}

					if !testCase.delete {
						err := ops.Update(
							context.TODO(),
							nil, // ReadTxn (unused)
							&frontend,
						)
						require.NoError(t, err, "Update")
					} else {
						err := ops.Delete(
							context.TODO(),
							nil, // ReadTxn (unused)
							&frontend,
						)
						require.NoError(t, err, "Delete")
					}

					// Prune to catch unexpected deletions.
					require.NoError(t,
						ops.Prune(
							context.TODO(),
							nil, // ReadTxn (unused)
							nil, // Iterator[*Frontend] (unused)
						),
						"Prune")

					out := DumpLBMaps(lbmaps, addr, false, nil)
					if !slices.Equal(out, testCase.maps) {
						t.Fatalf("BPF map contents differ!\nexpected:\n%s\nactual:\n%s", showMaps(testCase.maps), showMaps(out))
					}
				})
			}

			// Verify that the BPF maps are empty after the test set.
			require.Empty(t, DumpLBMaps(lbmaps, addr, false, nil), "BPF maps not empty")

			// Verify that all internal state has been cleaned up.
			require.Empty(t, ops.backendIDAlloc.entities, "Backend ID allocations remain")
			require.Empty(t, ops.serviceIDAlloc.entities, "Frontend ID allocations remain")
			require.Empty(t, ops.backendStates, "Backend state remain")
			require.Empty(t, ops.backendReferences, "Backend references remain")
			require.Empty(t, ops.nodePortAddrs, "NodePort addrs state remain")
		}
	}
}

// showMaps formats the map dumps as the Go code expected in the test cases.
func showMaps(m []MapDump) string {
	var w strings.Builder
	w.WriteString("[]mapDump{\n")
	for _, line := range m {
		w.WriteString("  \"")
		w.WriteString(line)
		w.WriteString("\",\n")
	}
	w.WriteString("},\n")
	return w.String()
}

type mapKeyValue struct {
	key   bpf.MapKey
	value bpf.MapValue
}
type mapSnapshot = []mapKeyValue

type mapSnapshots struct {
	services mapSnapshot
	backends mapSnapshot
	revNat   mapSnapshot
	affinity mapSnapshot
	srcRange mapSnapshot
}

func snapshotMaps(lbmaps LBMaps) (s mapSnapshots) {
	svcCB := func(svcKey lbmap.ServiceKey, svcValue lbmap.ServiceValue) {
		s.services = append(s.services, mapKeyValue{svcKey, svcValue})
	}
	if err := lbmaps.DumpService(svcCB); err != nil {
		panic(err)
	}

	beCB := func(beKey lbmap.BackendKey, beValue lbmap.BackendValue) {
		s.backends = append(s.backends, mapKeyValue{beKey, beValue})
	}
	if err := lbmaps.DumpBackend(beCB); err != nil {
		panic(err)
	}

	revCB := func(revKey lbmap.RevNatKey, revValue lbmap.RevNatValue) {
		s.revNat = append(s.revNat, mapKeyValue{revKey, revValue})
	}
	if err := lbmaps.DumpRevNat(revCB); err != nil {
		panic(err)
	}

	affCB := func(affKey *lbmap.AffinityMatchKey, affValue *lbmap.AffinityMatchValue) {
		s.affinity = append(s.revNat, mapKeyValue{affKey, affValue})
	}
	if err := lbmaps.DumpAffinityMatch(affCB); err != nil {
		panic(err)
	}

	srcRangeCB := func(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) {
		s.srcRange = append(s.srcRange, mapKeyValue{key, value})
	}
	if err := lbmaps.DumpSourceRange(srcRangeCB); err != nil {
		panic(err)
	}
	return
}

func (s *mapSnapshots) restore(lbmaps LBMaps) {
	for _, kv := range s.services {
		lbmaps.UpdateService(kv.key.(lbmap.ServiceKey), kv.value.(lbmap.ServiceValue))
	}
	for _, kv := range s.backends {
		lbmaps.UpdateBackend(kv.key.(lbmap.BackendKey), kv.value.(lbmap.BackendValue))
	}
	for _, kv := range s.revNat {
		lbmaps.UpdateRevNat(kv.key.(lbmap.RevNatKey), kv.value.(lbmap.RevNatValue))
	}
	for _, kv := range s.affinity {
		lbmaps.UpdateAffinityMatch(kv.key.(*lbmap.AffinityMatchKey), kv.value.(*lbmap.AffinityMatchValue))
	}
	for _, kv := range s.srcRange {
		lbmaps.UpdateSourceRange(kv.key.(lbmap.SourceRangeKey), kv.value.(*lbmap.SourceRangeValue))
	}
}
