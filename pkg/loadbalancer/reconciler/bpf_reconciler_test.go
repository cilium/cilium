// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
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

var (
	// special addresses that are replaced by the test runner.
	autoAddr = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("0.0.0.1"),
		L4Addr:      loadbalancer.L4Addr{},
		Scope:       0,
	}
	zeroAddr = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("0.0.0.3"),
		L4Addr:      loadbalancer.L4Addr{},
		Scope:       0,
	}

	extraFrontend = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("10.0.0.2"),
		L4Addr: loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     80,
		},
		Scope: 0,
	}

	// backend addresses
	backend1 = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("10.1.0.1"),
		L4Addr: loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     80,
		},
		Scope: 0,
	}
	backend2 = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("10.1.0.2"),
		L4Addr: loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     80,
		},
		Scope: 0,
	}

	// frontendAddrs are assigned to the <auto>/autoAddr. Each test set is run with
	// each of these.
	frontendAddrs = []loadbalancer.L3n4Addr{
		parseAddrPort("10.0.0.1:80"),
		parseAddrPort("[2001::1]:80"),
	}

	nodePortAddrs = []netip.Addr{
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("2002::1"),
	}
)

func parseAddrPort(s string) loadbalancer.L3n4Addr {
	addrS, portS, found := strings.Cut(s, "]:")
	if found {
		// IPv6
		addrS = addrS[1:] // drop [
	} else {
		// IPv4
		addrS, portS, found = strings.Cut(s, ":")
		if !found {
			panic("bad <ip:port>")
		}
	}
	addr := types.MustParseAddrCluster(addrS)
	port, _ := strconv.ParseInt(portS, 10, 16)
	return *loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		addr, uint16(port), loadbalancer.ScopeExternal,
	)

}

func dumpLBMapsWithReplace(lbmaps maps.LBMaps, feAddr loadbalancer.L3n4Addr, sanitizeIDs bool) (out []maps.MapDump) {
	replaceAddr := func(addr net.IP, port uint16) (s string) {
		s = addr.String()
		if addr.To4() == nil {
			s = "[" + s + "]"
		}
		s = fmt.Sprintf("%s:%d", s, port)
		if addr.IsUnspecified() {
			s = "<zero>"
			return
		}
		switch addr.String() {
		case feAddr.AddrCluster.String():
			s = "<auto>"
		case nodePortAddrs[0].String():
			s = "<nodePort>"
		case nodePortAddrs[1].String():
			s = "<nodePort>"
		}
		return
	}
	return maps.DumpLBMaps(lbmaps, sanitizeIDs, replaceAddr)
}

type testCase struct {
	name string

	// frontend and the associated service + backends.
	frontend loadbalancer.Frontend

	delete bool

	// maps and maglev are the dumped BPF maps. These should not be hand-written but rather
	// pasted in from the failing test case when a new test-case is added.
	// Sorted.
	maps, maglev []maps.MapDump
}

var testServiceName = loadbalancer.ServiceName{Name: "test", Namespace: "test"}

var baseService = loadbalancer.Service{
	Name:                   testServiceName,
	Source:                 source.Kubernetes,
	Labels:                 nil,
	NatPolicy:              loadbalancer.SVCNatPolicyNone,
	ExtTrafficPolicy:       loadbalancer.SVCTrafficPolicyLocal,
	IntTrafficPolicy:       loadbalancer.SVCTrafficPolicyLocal,
	SessionAffinity:        false,
	SessionAffinityTimeout: 0,
	ProxyRedirect:          nil,
	LoopbackHostPort:       false,
}

var baseFrontend = loadbalancer.Frontend{
	FrontendParams: loadbalancer.FrontendParams{
		ServiceName: testServiceName,
		PortName:    "", // Ignored, backends already resolved.
	},
	Backends: func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {},
	Status:   reconciler.StatusPending(),
}

var emptyInstances = func() part.Map[loadbalancer.BackendInstanceKey, loadbalancer.BackendParams] {
	part.RegisterKeyType(loadbalancer.BackendInstanceKey.Key)
	return part.Map[loadbalancer.BackendInstanceKey, loadbalancer.BackendParams]{}
}()

var baseBackend = newTestBackend(backend1, loadbalancer.BackendStateActive)
var nextBackendRevision = statedb.Revision(1)

func concatBe(bes loadbalancer.BackendsSeq2, be loadbalancer.BackendParams, rev statedb.Revision) loadbalancer.BackendsSeq2 {
	return func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {
		if !yield(be, rev) {
			return
		}
		bes(yield)
	}
}

func newTestBackend(addr loadbalancer.L3n4Addr, state loadbalancer.BackendState) loadbalancer.Backend {
	return loadbalancer.Backend{
		Address: addr,
		Instances: emptyInstances.Set(
			loadbalancer.BackendInstanceKey{ServiceName: testServiceName, SourcePriority: 0},
			loadbalancer.BackendParams{
				Address:   addr,
				NodeName:  "",
				PortNames: nil,
				Weight:    0,
				State:     state,
			},
		),
	}
}

// newTestCase creates a testCase from a function that manipulates the base service and frontends.
func newTestCase(name string, mod func(*loadbalancer.Service, *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend), maps []maps.MapDump, maglev []maps.MapDump) testCase {
	svc := baseService
	fe := baseFrontend
	delete, bes := mod(&svc, &fe)
	fe.Service = &svc
	for _, be := range bes {
		fe.Backends = concatBe(fe.Backends, *be.GetInstance(svc.Name), nextBackendRevision)
		nextBackendRevision++
	}
	return testCase{
		name:     name,
		frontend: fe,
		delete:   delete,
		maps:     maps,
		maglev:   maglev,
	}
}

func deleteFrontend(addr loadbalancer.L3n4Addr, typ loadbalancer.SVCType) func(*loadbalancer.Service, *loadbalancer.Frontend) (bool, []loadbalancer.Backend) {
	return func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (bool, []loadbalancer.Backend) {
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
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, nil
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"ClusterIP_1_backend",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"ClusterIP_2_backends",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2 :=
				newTestBackend(backend1, loadbalancer.BackendStateActive),
				newTestBackend(backend2, loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=2 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"ClusterIP_delete_backends",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, nil
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	// Test that adding another frontend allocates new IDs correctly.
	newTestCase(
		"ClusterIP_extra_frontend",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = extraFrontend
			return false, nil
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=10.0.0.2:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"ClusterIP_delete_extra",
		deleteFrontend(extraFrontend, ClusterIP),
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	// Adding the same frontend again won't reuse the ID as it should have been released.
	newTestCase(
		"ClusterIP_extra_frontend_again",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = extraFrontend
			return false, nil
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"REV: ID=3 ADDR=10.0.0.2:80",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=3 ADDR=10.0.0.2:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"ClusterIP_delete_extra_again",
		deleteFrontend(extraFrontend, ClusterIP),
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"ClusterIP_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
	),
}

var quarantineTestCases = []testCase{
	newTestCase(
		"Quarantine_2_active_backends",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2 :=
				newTestBackend(backend1, loadbalancer.BackendStateActive),
				newTestBackend(backend2, loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=2 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"Quarantine_1_active_1_quarantined",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2 :=
				newTestBackend(backend1, loadbalancer.BackendStateQuarantined),
				newTestBackend(backend2, loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=quarantined",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=1 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"Quarantine_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
	),
}

var nodePortTestCases = []testCase{
	newTestCase(
		"NodePort",

		// For NodePort we only create the surrogate entry with zero IP
		// address. From this additional services map entries are created
		// for each node IP address.

		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			be1, be2 :=
				newTestBackend(backend1, loadbalancer.BackendStateActive),
				newTestBackend(backend2, loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2}
		},

		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
		},
		[]maps.MapDump{
			"MAGLEV: ID=2 INNER=[1(511), 2(510)]",
		},
	),

	newTestCase(
		"NodePort_cleanup",
		deleteFrontend(zeroAddr, NodePort),
		[]maps.MapDump{},
		nil,
	),
}

var hostPortTestCases = []testCase{
	// HostPort. Essentially same as NodePort when zero address is used,
	// e.g. there's a service frontend for each Node IP address.
	newTestCase(
		"HostPort_zero",

		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = HostPort
			fe.Address = zeroAddr
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
		[]maps.MapDump{
			"MAGLEV: ID=2 INNER=[1(1021)]",
		},
	),

	newTestCase(
		"HostPort_zero_cleanup",
		deleteFrontend(zeroAddr, HostPort),
		[]maps.MapDump{},
		nil,
	),

	// HostPort with fixed address.
	newTestCase(
		"HostPort_fixed",

		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = HostPort
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"BE: ID=2 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=3 ADDR=<auto>",
			"SVC: ID=3 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
			"SVC: ID=3 ADDR=<auto>/TCP SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
		[]maps.MapDump{
			"MAGLEV: ID=3 INNER=[2(1021)]",
		},
	),

	newTestCase(
		"HostPort_fixed_cleanup",
		deleteFrontend(autoAddr, HostPort),
		[]maps.MapDump{},
		nil,
	),
}

var proxyTestCases = []testCase{
	newTestCase(
		"L7Proxy",

		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr

			// The port is stored as the backend ID in network byte-order, which is different
			// from how the backend ID is normally stored (host byte-order). Hence to make this
			// work on both little and big-endian machine's the port is set to a value that's the
			// same in both byte orders.
			svc.ProxyRedirect = &loadbalancer.ProxyRedirect{
				ProxyPort: 0x0a0a, // 2570
			}
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 L7Proxy=2570 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+l7-load-balancer",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+l7-load-balancer",
		},
		nil,
	),
	newTestCase(
		"L7Proxy_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
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
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			svc.NatPolicy = loadbalancer.SVCNatPolicyNat46
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+46x64",
		},
		nil,
	),

	newTestCase(
		"MiscFlags_Ext_Cluster",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			svc.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+InternalLocal+non-routable",
		},
		nil,
	),

	newTestCase(
		"MiscFlags_Int_Cluster",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+non-routable",
		},
		nil,
	),

	newTestCase(
		"MiscFlags_Both_Cluster",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr

			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster

			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+non-routable",
		},
		nil,
	),

	newTestCase(
		"MiscFlags_cleanup_1",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
	),

	newTestCase(
		"MiscFlags_ScopeInternal",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = HostPort
			fe.Address = extraFrontendInternal
			fe.Address.Scope = loadbalancer.ScopeInternal

			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=2 ADDR=10.0.0.2:80/TCP/i SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
		nil,
	),

	newTestCase(
		"MiscFlags_TwoTrafficPolicyScopes",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = HostPort
			fe.Address = extraFrontendInternal
			fe.Address.Scope = loadbalancer.ScopeInternal

			svc.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster

			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=2 ADDR=10.0.0.2:80/TCP/i SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+two-scopes",
		},
		nil,
	),

	newTestCase(
		"MiscFlags_cleanup_2",
		deleteFrontend(extraFrontendInternal, ClusterIP),
		[]maps.MapDump{},
		nil,
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
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = LoadBalancer
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=LoadBalancer+Local+InternalLocal",
		},
		nil,
	),

	newTestCase(
		"LoadBalancer_cleanup",
		deleteFrontend(autoAddr, LoadBalancer),
		[]maps.MapDump{},
		nil,
	),
}

var externalIPTestCases = []testCase{
	newTestCase(
		"ExternalIPs",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ExternalIPs
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ExternalIPs+Local+InternalLocal",
		},
		nil,
	),

	newTestCase(
		"ExternalIPs_cleanup",
		deleteFrontend(autoAddr, ExternalIPs),
		[]maps.MapDump{},
		nil,
	),
}

var localRedirectTestCases = []testCase{
	// If a frontend has a redirect set to another service it will have the "LocalRedirect" flag.
	newTestCase(
		"LocalRedirect",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.RedirectTo = &loadbalancer.ServiceName{Name: "foo", Namespace: "bar"}
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=LocalRedirect+Local+InternalLocal",
		},
		nil,
	),

	newTestCase(
		"LocalRedirect_cleanup",
		deleteFrontend(autoAddr, LocalRedirect),
		[]maps.MapDump{},
		nil,
	),
}

var sessionAffinityTestCases = []testCase{
	newTestCase(
		"SessionAffinity",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = true
			svc.SessionAffinityTimeout = time.Second
			be1, be2 :=
				newTestBackend(backend1, loadbalancer.BackendStateActive),
				newTestBackend(backend2, loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2}
		},

		[]maps.MapDump{
			"AFF: ID=1 BEID=1",
			"AFF: ID=1 BEID=2",
			"AFF: ID=2 BEID=1",
			"AFF: ID=2 BEID=2",
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=1 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=1 COUNT=2 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
		},
		[]maps.MapDump{
			"MAGLEV: ID=2 INNER=[1(511), 2(510)]",
		},
	),

	newTestCase(
		"SessionAffinity_quarantine",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = true
			svc.SessionAffinityTimeout = time.Second
			be1, be2 :=
				newTestBackend(backend1, loadbalancer.BackendStateQuarantined),
				newTestBackend(backend2, loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2}
		},

		[]maps.MapDump{
			"AFF: ID=1 BEID=2",
			"AFF: ID=2 BEID=2",
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=quarantined",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<zero>",
			"REV: ID=2 ADDR=<nodePort>",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=1 COUNT=1 QCOUNT=1 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=<zero>/TCP SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=1 COUNT=1 QCOUNT=1 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
		},
		[]maps.MapDump{
			"MAGLEV: ID=2 INNER=[2(1021)]",
		},
	),
	newTestCase(
		"SessionAffinity_cleanup_1",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			// Even if SessionAffinity was turned off the affinity map should be cleaned.
			svc.SessionAffinity = false
			return true, nil
		},
		[]maps.MapDump{},
		nil,
	),

	newTestCase(
		"SessionAffinity_add_to_disable",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = true
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"AFF: ID=3 BEID=3",
			"AFF: ID=4 BEID=3",
			"BE: ID=3 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=3 ADDR=<zero>",
			"REV: ID=4 ADDR=<nodePort>",
			"SVC: ID=3 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=3 ADDR=<zero>/TCP SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=4 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
			"SVC: ID=4 ADDR=<nodePort>/TCP SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+sessionAffinity",
		},
		[]maps.MapDump{
			"MAGLEV: ID=4 INNER=[3(1021)]",
		},
	),

	// Disable session affinity to verify that the affinity match maps are cleaned up.
	newTestCase(
		"SessionAffinity_disable",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			svc.SessionAffinity = false
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"BE: ID=3 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=3 ADDR=<zero>",
			"REV: ID=4 ADDR=<nodePort>",
			"SVC: ID=3 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=3 ADDR=<zero>/TCP SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
			"SVC: ID=4 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
			"SVC: ID=4 ADDR=<nodePort>/TCP SLOT=1 BEID=3 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
		},
		[]maps.MapDump{
			"MAGLEV: ID=4 INNER=[3(1021)]",
		},
	),

	newTestCase(
		"SessionAffinity_cleanup_2",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = NodePort
			fe.Address = zeroAddr
			// Flip SessionAffinity on again to verify that it doesn't affect the deletion
			// even when this frontend was reconciled without SessionAffinity.
			svc.SessionAffinity = true
			return true, nil
		},
		[]maps.MapDump{},
		nil,
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

type setWithAlgo struct {
	testCaseSet []testCase
	algo        string
}

var perServiceAlgorithmCases = []setWithAlgo{
	{
		testCaseSet: []testCase{
			newTestCase(
				"NodePort_1_backend_explicitMaglev",
				func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
					fe.Type = NodePort
					fe.Address = zeroAddr
					if svc.Annotations == nil {
						svc.Annotations = make(map[string]string)
					}
					svc.Annotations[annotation.ServiceLoadBalancingAlgorithm] = loadbalancer.LBAlgorithmMaglev
					return false, []loadbalancer.Backend{baseBackend}
				},
				[]maps.MapDump{
					"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
					"REV: ID=1 ADDR=<zero>",
					"REV: ID=2 ADDR=<nodePort>",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=maglev AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=maglev AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
				},
				[]maps.MapDump{
					"MAGLEV: ID=2 INNER=[1(1021)]",
				},
			),
			newTestCase(
				"NodePorts_explicitMaglev_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
			),
		},
		algo: loadbalancer.LBAlgorithmRandom,
	},
	{
		testCaseSet: []testCase{
			newTestCase(
				"NodePort_1_backend_noExplicitMaglev",
				func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
					fe.Type = NodePort
					fe.Address = zeroAddr
					return false, []loadbalancer.Backend{baseBackend}
				},
				[]maps.MapDump{
					"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
					"REV: ID=1 ADDR=<zero>",
					"REV: ID=2 ADDR=<nodePort>",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
				},
				nil,
			),
			newTestCase(
				"NodePorts_noExplicitMaglev_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
			),
		},
		algo: loadbalancer.LBAlgorithmRandom,
	},
	{
		testCaseSet: []testCase{
			newTestCase(
				"NodePort_1_backend_explicitRandom",
				func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
					fe.Type = NodePort
					fe.Address = zeroAddr
					if svc.Annotations == nil {
						svc.Annotations = make(map[string]string)
					}
					svc.Annotations[annotation.ServiceLoadBalancingAlgorithm] = loadbalancer.LBAlgorithmRandom
					return false, []loadbalancer.Backend{baseBackend}
				},
				[]maps.MapDump{
					"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
					"REV: ID=1 ADDR=<zero>",
					"REV: ID=2 ADDR=<nodePort>",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=random AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=random AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
				},
				nil,
			),
			newTestCase(
				"NodePorts_explicitRandom_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
			),
		},
		algo: loadbalancer.LBAlgorithmMaglev,
	},
	{
		testCaseSet: []testCase{
			newTestCase(
				"NodePort_1_backend_noExplicitRandom",
				func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
					fe.Type = NodePort
					fe.Address = zeroAddr
					return false, []loadbalancer.Backend{baseBackend}
				},
				[]maps.MapDump{
					"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
					"REV: ID=1 ADDR=<zero>",
					"REV: ID=2 ADDR=<nodePort>",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=1 ADDR=<zero>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal+non-routable",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
					"SVC: ID=2 ADDR=<nodePort>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=NodePort+Local+InternalLocal",
				},
				[]maps.MapDump{
					"MAGLEV: ID=2 INNER=[1(1021)]",
				},
			),
			newTestCase(
				"NodePorts_noExplicitMaglev_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
			),
		},
		algo: loadbalancer.LBAlgorithmMaglev,
	},
}

func TestBPFOps(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)

	maglevCfg, err := maglev.UserConfig{
		TableSize: 1021,
		HashSeed:  maglev.DefaultHashSeed,
	}.ToConfig()
	require.NoError(t, err, "ToConfig")
	maglev := maglev.New(maglevCfg, lc)

	// Enable features.
	extCfg := loadbalancer.ExternalConfig{
		ZoneMapper:           &option.DaemonConfig{},
		EnableIPv4:           true,
		EnableIPv6:           true,
		KubeProxyReplacement: true,
		EnableHostPort:       true,
	}

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})
	cfg.EnableExperimentalLB = true

	var lbmaps maps.LBMaps
	if testutils.IsPrivileged() {
		r := &maps.BPFLBMaps{
			Log:       log,
			Pinned:    false,
			Cfg:       cfg,
			ExtCfg:    extCfg,
			MaglevCfg: maglevCfg,
		}
		lc.Append(r)
		lbmaps = r
	} else {
		lbmaps = maps.NewFakeLBMaps()
	}

	// Insert node addrs used for NodePort/HostPort
	db := statedb.New()
	nodeAddrs, _ := tables.NewNodeAddressTable()
	require.NoError(t, db.RegisterTable(nodeAddrs))
	wtxn := db.WriteTxn(nodeAddrs)
	for _, n := range nodePortAddrs {
		na := tables.NodeAddress{
			Addr:       n,
			NodePort:   true,
			Primary:    true,
			DeviceName: "lol0",
		}
		_, _, err := nodeAddrs.Insert(wtxn, na)
		require.NoError(t, err)
	}
	wtxn.Commit()

	runTests := func(ops *BPFOps, testCaseSet []testCase, algo string, addr loadbalancer.L3n4Addr, validateMaglev bool) {
		for _, testCase := range testCaseSet {
			t.Run(fmt.Sprintf("%s/%s/ipv6:%v", testCase.name, algo, addr.IsIPv6()), func(t *testing.T) {
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
						db.ReadTxn(),
						0,
						&frontend,
					)
					require.NoError(t, err, "Update")
				} else {
					err := ops.Delete(
						context.TODO(),
						nil, // ReadTxn (unused)
						0,
						&frontend,
					)
					require.NoError(t, err, "Delete")
				}

				// Prune to catch unexpected deletions.
				require.NoError(t,
					ops.Prune(
						context.TODO(),
						nil, // ReadTxn (unused)
						nil, // Iterator[*loadbalancer.Frontend] (unused)
					),
					"Prune")

				nonMaglev := []string{}
				maglev := []string{}
				for _, v := range dumpLBMapsWithReplace(lbmaps, addr, false) {
					if strings.HasPrefix(v, "MAGLEV") {
						maglev = append(maglev, v)
					} else {
						nonMaglev = append(nonMaglev, v)
					}
				}

				if !slices.Equal(nonMaglev, testCase.maps) {
					t.Fatalf("BPF map contents differ!\nexpected:\n%s\nactual:\n%s", showMaps(testCase.maps), showMaps(nonMaglev))
				}
				wantMaglev := []string{}
				if validateMaglev {
					wantMaglev = testCase.maglev
				}
				if !slices.Equal(maglev, wantMaglev) {
					t.Fatalf("BPF map contents differ for Maglev!\nexpected:\n%s\nactual:\n%s", showMaps(wantMaglev), showMaps(maglev))
				}
			})
		}

		// Verify that the BPF maps are empty after the test set.
		maps := dumpLBMapsWithReplace(lbmaps, addr, false)
		require.Empty(t, maps, "BPF maps not empty")

		// Verify that all internal state has been cleaned up.
		require.Empty(t, ops.backendIDAlloc.entities, "Backend ID allocations remain")
		require.Empty(t, ops.serviceIDAlloc.entities, "Frontend ID allocations remain")
		require.Empty(t, ops.backendStates, "Backend state remain")
		require.Empty(t, ops.backendReferences, "Backend references remain")
		require.Empty(t, ops.nodePortAddrByPort, "NodePort addrs state remain")
	}

	for _, testCaseSet := range testCases {
		// Run each set with Random and Maglev load balancing algos.
		for _, algo := range []string{loadbalancer.LBAlgorithmRandom, loadbalancer.LBAlgorithmMaglev} {
			testCaseSet := testCaseSet
			if algo == loadbalancer.LBAlgorithmMaglev {
				for i, tc := range testCaseSet {
					for j, line := range tc.maps {
						line = strings.Replace(line, "LBALG=undef", "LBALG=undef", 1)
						testCaseSet[i].maps[j] = line
					}
				}
			}
			// Run each set with IPv4 and IPv6 addresses.
			for _, addr := range frontendAddrs {
				// For each set of test cases, use a fresh instance so each set gets
				// fresh IDs.
				external := extCfg
				cfg := cfg
				cfg.LBAlgorithm = algo
				p := bpfOpsParams{
					Lifecycle:      lc,
					Log:            log,
					Config:         cfg,
					ExternalConfig: external,
					LBMaps:         lbmaps,
					Maglev:         maglev,
					DB:             db,
					NodeAddresses:  nodeAddrs,
				}

				ops := newBPFOps(p)
				validateMaglev := algo == loadbalancer.LBAlgorithmMaglev
				runTests(ops, testCaseSet, algo, addr, validateMaglev)
			}
		}
	}

	cfg.AlgorithmAnnotation = true
	for _, setWithAlgo := range perServiceAlgorithmCases {
		// Run each set with IPv4 and IPv6 addresses.
		for _, addr := range frontendAddrs {
			// For each set of test cases, use a fresh instance so each set gets
			// fresh IDs.
			external := extCfg
			cfg.LBAlgorithm = setWithAlgo.algo
			p := bpfOpsParams{
				Lifecycle:      lc,
				Log:            log,
				Config:         cfg,
				ExternalConfig: external,
				LBMaps:         lbmaps,
				Maglev:         maglev,
				DB:             db,
				NodeAddresses:  nodeAddrs,
			}
			ops := newBPFOps(p)
			runTests(ops, setWithAlgo.testCaseSet, setWithAlgo.algo, addr, true)
		}
	}
}

// showMaps formats the map dumps as the Go code expected in the test cases.
func showMaps(m []maps.MapDump) string {
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
