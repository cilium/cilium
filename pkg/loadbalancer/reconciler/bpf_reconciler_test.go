// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
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
	autoAddr = loadbalancer.NewL3n4Addr(
		loadbalancer.NONE,
		types.MustParseAddrCluster("0.0.0.1"),
		0,
		loadbalancer.ScopeExternal,
	)
	zeroAddr = loadbalancer.NewL3n4Addr(
		loadbalancer.NONE,
		types.MustParseAddrCluster("0.0.0.3"),
		0,
		loadbalancer.ScopeExternal,
	)
	extraFrontend = loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.0.0.2"),
		80,
		loadbalancer.ScopeExternal,
	)

	// backend addresses
	backend1 = loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.1.0.1"),
		80,
		loadbalancer.ScopeExternal,
	)
	backend2 = loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		types.MustParseAddrCluster("10.1.0.2"),
		80,
		loadbalancer.ScopeExternal,
	)

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

func withClusterID(be loadbalancer.L3n4Addr, clusterID uint32) loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(
		be.Protocol(),
		types.AddrClusterFrom(be.AddrCluster().Addr(), clusterID),
		be.Port(), be.Scope(),
	)
}

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
	return loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		addr, uint16(port), loadbalancer.ScopeExternal,
	)

}

func dumpLBMapsWithReplace(lbmaps maps.LBMaps, feAddr loadbalancer.L3n4Addr, sanitizeIDs bool) (out []maps.MapDump) {
	replaceAddr := func(addr types.AddrCluster, port uint16) (s string) {
		s = addr.String()
		if !addr.Is4() {
			s = "[" + s + "]"
		}
		s = fmt.Sprintf("%s:%d", s, port)
		if addr.IsUnspecified() {
			s = "<zero>"
			return
		}
		switch addr.String() {
		case feAddr.AddrCluster().String():
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

	// expectErr when true causes UpdateService to fail on backend slots
	// and expects Update to return an error.
	expectErr bool

	// maps and maglev are the dumped BPF maps. These should not be hand-written but rather
	// pasted in from the failing test case when a new test-case is added.
	// Sorted.
	maps, maglev []maps.MapDump
}

// faultyLBMaps wraps an LBMaps and can inject errors on UpdateService.
type faultyLBMaps struct {
	maps.LBMaps
	fail bool
}

func (m *faultyLBMaps) UpdateService(key maps.ServiceKey, value maps.ServiceValue) error {
	if m.fail && key.GetBackendSlot() > 0 {
		return errors.New("update service failed")
	}
	return m.LBMaps.UpdateService(key, value)
}

var testServiceName = loadbalancer.NewServiceName("test", "test")

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
	Backends: func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {},
	Status:   reconciler.StatusPending(),
}

var baseBackend = newTestBackend(backend1, loadbalancer.BackendStateActive)
var nextBackendRevision = statedb.Revision(1)

func concatBe(bes loadbalancer.BackendsSeq2, be loadbalancer.Backend, rev statedb.Revision) loadbalancer.BackendsSeq2 {
	return func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
		if !yield(&be, rev) {
			return
		}
		bes(yield)
	}
}

func newTestBackend(addr loadbalancer.L3n4Addr, state loadbalancer.BackendState) loadbalancer.Backend {
	be := loadbalancer.Backend{
		ServiceName: testServiceName,
		Address:     addr,
		NodeName:    "",
		PortNames:   nil,
		Weight:      0,
		State:       state,
		Source:      source.Kubernetes,
	}
	be.SetSourcePriority(0)
	return be
}

// newTestCase creates a testCase from a function that manipulates the base service and frontends.
func newTestCase(name string, mod func(*loadbalancer.Service, *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend), maps []maps.MapDump, maglev []maps.MapDump, expectErr bool) testCase {
	svc := baseService
	fe := baseFrontend
	delete, bes := mod(&svc, &fe)
	fe.Service = &svc
	for _, be := range bes {
		be.ServiceName = loadbalancer.ServiceName{}
		be.SetSourcePriority(0)
		fe.Backends = concatBe(fe.Backends, be, nextBackendRevision)
		nextBackendRevision++
	}
	return testCase{
		name:      name,
		frontend:  fe,
		delete:    delete,
		expectErr: expectErr,
		maps:      maps,
		maglev:    maglev,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=2 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	newTestCase(
		"ClusterIP_add_backends_with_cluster_id",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			be1, be2, be3, be4 :=
				newTestBackend(backend1, loadbalancer.BackendStateActive),
				newTestBackend(backend2, loadbalancer.BackendStateActive),
				newTestBackend(withClusterID(backend2, 10), loadbalancer.BackendStateActive),
				newTestBackend(withClusterID(backend2, 20), loadbalancer.BackendStateActive)
			return false, []loadbalancer.Backend{be1, be2, be3, be4}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"BE: ID=3 ADDR=10.1.0.2@10:80/TCP STATE=active",
			"BE: ID=4 ADDR=10.1.0.2@20:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=4 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=3 BEID=3 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=4 BEID=4 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=10.0.0.2:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=2 ADDR=10.0.0.2:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	newTestCase(
		"ClusterIP_delete_extra",
		deleteFrontend(extraFrontend, ClusterIP),
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=10.0.0.2:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=3 ADDR=10.0.0.2:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	newTestCase(
		"ClusterIP_delete_extra_again",
		deleteFrontend(extraFrontend, ClusterIP),
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	newTestCase(
		"ClusterIP_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=2 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=1 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=2 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	newTestCase(
		"Quarantine_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
		false,
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
		false,
	),

	newTestCase(
		"NodePort_cleanup",
		deleteFrontend(zeroAddr, NodePort),
		[]maps.MapDump{},
		nil,
		false,
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
		false,
	),

	newTestCase(
		"HostPort_zero_cleanup",
		deleteFrontend(zeroAddr, HostPort),
		[]maps.MapDump{},
		nil,
		false,
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
		false,
	),

	newTestCase(
		"HostPort_fixed_cleanup",
		deleteFrontend(autoAddr, HostPort),
		[]maps.MapDump{},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 L7Proxy=2570 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+l7-load-balancer",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+l7-load-balancer",
		},
		nil,
		false,
	),
	newTestCase(
		"L7Proxy_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
		false,
	),
}

var extraFrontendInternal = loadbalancer.NewL3n4Addr(
	extraFrontend.Protocol(),
	extraFrontend.AddrCluster(),
	extraFrontend.Port(),
	loadbalancer.ScopeInternal,
)

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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable+46x64",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+InternalLocal+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+non-routable",
		},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+non-routable",
		},
		nil,
		false,
	),

	newTestCase(
		"MiscFlags_cleanup_1",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
		false,
	),

	newTestCase(
		"MiscFlags_ScopeInternal",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = HostPort
			fe.Address = extraFrontendInternal

			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=2 ADDR=10.0.0.2:80/TCP/i SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+InternalLocal",
		},
		nil,
		false,
	),

	newTestCase(
		"MiscFlags_TwoTrafficPolicyScopes",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = HostPort
			fe.Address = extraFrontendInternal

			svc.ExtTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
			svc.IntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster

			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=2 ADDR=10.0.0.2:80",
			"SVC: ID=2 ADDR=10.0.0.2:80/TCP/i SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=HostPort+Local+two-scopes",
		},
		nil,
		false,
	),

	newTestCase(
		"MiscFlags_cleanup_2",
		deleteFrontend(extraFrontendInternal, ClusterIP),
		[]maps.MapDump{},
		nil,
		false,
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
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=LoadBalancer+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=LoadBalancer+Local+InternalLocal",
		},
		nil,
		false,
	),

	newTestCase(
		"LoadBalancer_cleanup",
		deleteFrontend(autoAddr, LoadBalancer),
		[]maps.MapDump{},
		nil,
		false,
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
		false,
	),

	newTestCase(
		"ExternalIPs_cleanup",
		deleteFrontend(autoAddr, ExternalIPs),
		[]maps.MapDump{},
		nil,
		false,
	),
}

var localRedirectTestCases = []testCase{
	// If a frontend has a redirect set to another service it will have the "LocalRedirect" flag.
	newTestCase(
		"LocalRedirect",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = LocalRedirect
			svcName := loadbalancer.NewServiceName("bar", "foo")
			fe.RedirectTo = &svcName
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{}
		},
		[]maps.MapDump{
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=LocalRedirect+Local+InternalLocal",
		},
		nil,
		false,
	),

	newTestCase(
		"LocalRedirect_cleanup",
		deleteFrontend(autoAddr, LocalRedirect),
		[]maps.MapDump{},
		nil,
		false,
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
		false,
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
		false,
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
		false,
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
		false,
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
		false,
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
		false,
	),
}

var globalAffinityTestCases = []testCase{
	newTestCase(
		"GlobalAffinity_Port80",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = loadbalancer.NewL3n4Addr("TCP", types.AddrClusterFrom(netip.MustParseAddr("10.0.2.1"), 0), 80, loadbalancer.ScopeExternal)
			fe.ServiceName = loadbalancer.NewServiceName("mysvc", "default")
			svc.SessionAffinity = true
			svc.Annotations = map[string]string{
				annotation.GlobalAffinity: "true",
			}
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"AFF: ID=1 BEID=1",
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"GLOBAL_AFFINITY: ID=1 AFF_ID=1",
			"REV: ID=1 ADDR=10.0.2.1:80",
			"SVC: ID=0 ADDR=10.0.2.1:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=10.0.2.1:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=10.0.2.1:80/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
		},
		nil,
		false,
	),
	newTestCase(
		"GlobalAffinity_cleanup_Port80",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = loadbalancer.NewL3n4Addr("TCP", types.AddrClusterFrom(netip.MustParseAddr("10.0.2.1"), 0), 80, loadbalancer.ScopeExternal)
			fe.ServiceName = loadbalancer.NewServiceName("mysvc", "default")
			return true, nil
		},
		[]maps.MapDump{},
		nil,
		false,
	),
}

var globalAffinityNegativeTestCases = []testCase{
	newTestCase(
		"GlobalAffinity_Svc1_Port80",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = loadbalancer.NewL3n4Addr("TCP", types.AddrClusterFrom(netip.MustParseAddr("10.0.2.1"), 0), 80, loadbalancer.ScopeExternal)
			fe.ServiceName = loadbalancer.NewServiceName("mysvc1", "default")
			svc.SessionAffinity = true
			svc.Annotations = map[string]string{
				annotation.GlobalAffinity: "true",
			}
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"AFF: ID=1 BEID=1",
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"GLOBAL_AFFINITY: ID=1 AFF_ID=1",
			"REV: ID=1 ADDR=10.0.2.1:80",
			"SVC: ID=0 ADDR=10.0.2.1:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=10.0.2.1:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=10.0.2.1:80/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
		},
		nil,
		false,
	),
	newTestCase(
		"GlobalAffinity_Svc2_Port80",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = loadbalancer.NewL3n4Addr("TCP", types.AddrClusterFrom(netip.MustParseAddr("10.0.2.2"), 0), 80, loadbalancer.ScopeExternal)
			fe.ServiceName = loadbalancer.NewServiceName("mysvc2", "default")
			svc.SessionAffinity = true
			svc.Annotations = map[string]string{
				annotation.GlobalAffinity: "true",
			}
			return false, []loadbalancer.Backend{baseBackend}
		},
		[]maps.MapDump{
			"AFF: ID=1 BEID=1",
			"AFF: ID=2 BEID=1",
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"GLOBAL_AFFINITY: ID=1 AFF_ID=1",
			"GLOBAL_AFFINITY: ID=2 AFF_ID=2",
			"REV: ID=1 ADDR=10.0.2.1:80",
			"REV: ID=2 ADDR=10.0.2.2:80",
			"SVC: ID=0 ADDR=10.0.2.1:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=0 ADDR=10.0.2.2:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=10.0.2.1:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=1 ADDR=10.0.2.1:80/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=10.0.2.2:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=10.0.2.2:80/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
		},
		nil,
		false,
	),
	newTestCase(
		"GlobalAffinity_Svc1_cleanup",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = loadbalancer.NewL3n4Addr("TCP", types.AddrClusterFrom(netip.MustParseAddr("10.0.2.1"), 0), 80, loadbalancer.ScopeExternal)
			fe.ServiceName = loadbalancer.NewServiceName("mysvc1", "default")
			return true, nil
		},
		[]maps.MapDump{
			"AFF: ID=2 BEID=1",
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"GLOBAL_AFFINITY: ID=2 AFF_ID=2",
			"REV: ID=2 ADDR=10.0.2.2:80",
			"SVC: ID=0 ADDR=10.0.2.2:0/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=2 ADDR=10.0.2.2:80/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
			"SVC: ID=2 ADDR=10.0.2.2:80/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+sessionAffinity+non-routable",
		},
		nil,
		false,
	),
	newTestCase(
		"GlobalAffinity_Svc2_cleanup",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (delete bool, bes []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = loadbalancer.NewL3n4Addr("TCP", types.AddrClusterFrom(netip.MustParseAddr("10.0.2.2"), 0), 80, loadbalancer.ScopeExternal)
			fe.ServiceName = loadbalancer.NewServiceName("mysvc2", "default")
			return true, nil
		},
		[]maps.MapDump{},
		nil,
		false,
	),
}

// mapErrorTestCases exercises the UpdateService error path.
var mapErrorTestCases = []testCase{
	// Step 1: Create a ClusterIP with one backend. This succeeds and establishes
	// backendReferences[fe] = {backend1}.
	newTestCase(
		"MapError_setup_1_backend",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (bool, []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{
				newTestBackend(backend1, loadbalancer.BackendStateActive),
			}
		},
		[]maps.MapDump{
			"BE: ID=1 ADDR=10.1.0.1:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	// Step 2: Switch to backend2 with an error injected. updateBackendRevision
	// runs for backend2 (creating backendStates[backend2]) but upsertService
	// fails on the slot, so updateReferences is skipped. The invariant check
	// in runTests verifies that backendStates[backend2].addr is still set.
	newTestCase(
		"MapError_update_service_fails",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (bool, []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{
				newTestBackend(backend2, loadbalancer.BackendStateActive),
			}
		},
		nil, // maps not checked on error
		nil,
		true,
	),

	// Step 3: Retry without the error. The reconciler recovers and proceeds normally.
	newTestCase(
		"MapError_retry_succeeds",
		func(svc *loadbalancer.Service, fe *loadbalancer.Frontend) (bool, []loadbalancer.Backend) {
			fe.Type = ClusterIP
			fe.Address = autoAddr
			return false, []loadbalancer.Backend{
				newTestBackend(backend2, loadbalancer.BackendStateActive),
			}
		},
		[]maps.MapDump{
			"BE: ID=2 ADDR=10.1.0.2:80/TCP STATE=active",
			"REV: ID=1 ADDR=<auto>",
			"SVC: ID=0 ADDR=<auto>/ANY SLOT=0 LBALG=undef AFFTimeout=0 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=0 LBALG=undef AFFTimeout=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
			"SVC: ID=1 ADDR=<auto>/TCP SLOT=1 BEID=2 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+Local+InternalLocal+non-routable",
		},
		nil,
		false,
	),

	// Step 4: Clean up.
	newTestCase(
		"MapError_cleanup",
		deleteFrontend(autoAddr, ClusterIP),
		[]maps.MapDump{},
		nil,
		false,
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
	globalAffinityTestCases,
	globalAffinityNegativeTestCases,
	mapErrorTestCases,
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
				false,
			),
			newTestCase(
				"NodePorts_explicitMaglev_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
				false,
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
				false,
			),
			newTestCase(
				"NodePorts_noExplicitMaglev_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
				false,
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
				false,
			),
			newTestCase(
				"NodePorts_explicitRandom_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
				false,
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
				false,
			),
			newTestCase(
				"NodePorts_noExplicitMaglev_cleanup",
				deleteFrontend(zeroAddr, NodePort),
				[]maps.MapDump{},
				nil,
				false,
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
		DefaultLBServiceIPAM: "lbipam",
		EnableLBIPAM:         true,
		EnableNodeIPAM:       false,
	}

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})

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
	nodeAddrs, err := tables.NewNodeAddressTable(db)
	require.NoError(t, err)
	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)
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

	faultMaps := &faultyLBMaps{LBMaps: lbmaps}

	runTests := func(ops *BPFOps, testCaseSet []testCase, algo string, addr loadbalancer.L3n4Addr, validateMaglev bool) {
		for _, testCase := range testCaseSet {
			t.Run(fmt.Sprintf("%s/%s/ipv6:%v", testCase.name, algo, addr.IsIPv6()), func(t *testing.T) {
				frontend := testCase.frontend

				switch frontend.Address.String() {
				case autoAddr.String():
					frontend.Address = addr
				case zeroAddr.String():
					if addr.IsIPv6() {
						frontend.Address = loadbalancer.NewL3n4Addr(
							addr.Protocol(),
							types.AddrClusterFrom(netip.IPv6Unspecified(), 0),
							addr.Port(),
							addr.Scope(),
						)
					} else {
						frontend.Address = loadbalancer.NewL3n4Addr(
							addr.Protocol(),
							types.AddrClusterFrom(netip.IPv4Unspecified(), 0),
							addr.Port(),
							addr.Scope(),
						)
					}
				}

				if testCase.expectErr {
					faultMaps.fail = true
					defer func() { faultMaps.fail = false }()
				}

				if !testCase.delete {
					// Insert frontend into statedb so that updateFrontend can find it!
					wtxn := db.WriteTxn(frontends)
					_, _, err = frontends.Insert(wtxn, &frontend)
					require.NoError(t, err)
					wtxn.Commit()

					err := ops.Update(
						context.TODO(),
						db.ReadTxn(),
						0,
						&frontend,
					)
					if testCase.expectErr {
						require.Error(t, err, "Update")
					} else {
						require.NoError(t, err, "Update")

						// Write back to statedb with the allocated ID!
						wtxn := db.WriteTxn(frontends)
						cloned := frontend.Clone()
						_, _, err = frontends.Insert(wtxn, cloned)
						require.NoError(t, err)
						wtxn.Commit()
					}

					// Invariant: every backendStates entry must have a non-zero addr.
					for beAddr, state := range ops.backendStates {
						require.NotEqual(t, loadbalancer.L3n4Addr{}, state.addr,
							"backendStates[%s] has zero-value addr; would panic in orphan cleanup", beAddr)
					}
				} else {
					// Remove frontend from statedb!
					wtxn := db.WriteTxn(frontends)
					_, _, err = frontends.Delete(wtxn, &frontend)
					require.NoError(t, err)
					wtxn.Commit()

					err := ops.Delete(
						context.TODO(),
						db.ReadTxn(),
						0,
						&frontend,
					)
					require.NoError(t, err, "Delete")
				}

				// Skip map validation and prune for error cases since the BPF maps
				// are in a partially inconsistent state after a failed Update.
				if testCase.expectErr {
					return
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
		require.Empty(t, ops.backendIDAlloc.idToAddr, "Backend ID allocations remain")
		require.Empty(t, ops.serviceIDAlloc.idToAddr, "Frontend ID allocations remain")
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
					LBMaps:         faultMaps,
					Maglev:         maglev,
					DB:             db,
					NodeAddresses:  nodeAddrs,
					Frontends:      frontends,
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
				LBMaps:         faultMaps,
				Maglev:         maglev,
				DB:             db,
				NodeAddresses:  nodeAddrs,
				Frontends:      frontends,
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

func TestGlobalAffinityRestart(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)
	db := statedb.New()

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})
	extCfg := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: false} // Only IPv4 for simplicity

	lbmaps := maps.NewFakeLBMaps()

	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)

	p := bpfOpsParams{
		Lifecycle:      lc,
		Log:            log,
		Config:         cfg,
		ExternalConfig: extCfg,
		LBMaps:         lbmaps,
		DB:             db,
		NodeAddresses:  nil, // Not needed for ClusterIP
		Frontends:      frontends,
	}

	ops := newBPFOps(p)

	// Create a service with two ports
	svcName := loadbalancer.NewServiceName("mysvc", "default")
	fe1 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.1"), 80, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: &loadbalancer.Service{
			Name:            svcName,
			SessionAffinity: true,
			Annotations: map[string]string{
				annotation.GlobalAffinity: "true",
			},
		},
	}
	fe2 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.1"), 443, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: fe1.Service,
	}

	fe1.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}
	fe2.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}

	// Insert into statedb
	wtxn := db.WriteTxn(frontends)
	_, _, err = frontends.Insert(wtxn, &fe1)
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, &fe2)
	require.NoError(t, err)
	wtxn.Commit()

	// Reconcile fe1
	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe1)
	require.NoError(t, err)

	wtxn = db.WriteTxn(frontends)
	cloned1 := fe1.Clone()
	_, _, err = frontends.Insert(wtxn, cloned1)
	require.NoError(t, err)
	wtxn.Commit()

	// Reconcile fe2
	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe2)
	require.NoError(t, err)

	wtxn = db.WriteTxn(frontends)
	cloned2 := fe2.Clone()
	_, _, err = frontends.Insert(wtxn, cloned2)
	require.NoError(t, err)
	wtxn.Commit()

	// Verify shared ID in map
	// We expect both to map to same affinity ID!
	// Let's assume it picks fe1's ID (which should be 1 if it was first).
	
	// Now simulate restart!
	// Create a NEW BPFOps instance with the SAME FakeLBMaps!
	ops2 := newBPFOps(p)

	// In real restore, IDs are restored from BPF maps into restoredServiceIDs.
	// We populate it manually here to simulate that.
	ops2.restoredServiceIDs = map[loadbalancer.L3n4Addr]loadbalancer.ServiceID{
		fe1.Address: fe1.ID,
		fe2.Address: fe2.ID,
	}

	// Reconcile again with ops2, but in REVERSE order!
	// This tests that processing order doesn't matter!
	err = ops2.Update(context.TODO(), db.ReadTxn(), 0, &fe2)
	require.NoError(t, err)
	err = ops2.Update(context.TODO(), db.ReadTxn(), 0, &fe1)
	require.NoError(t, err)

	// Verify maps again! They should still have the SAME shared ID!
	// We check that `globalAffinityIDs` (if we still used it) or the BPF map state is correct.
	// Since we use BPF maps directly via FakeLBMaps, we can dump them and verify.
	
	var aff1, aff2 uint16
	lbmaps.DumpGlobalAffinity(func(revNatID uint16, affinityID uint16, ipv6 bool) {
		if revNatID == uint16(fe1.ID) {
			aff1 = affinityID
		}
		if revNatID == uint16(fe2.ID) {
			aff2 = affinityID
		}
	})
	
	require.Equal(t, aff1, aff2, "Affinity IDs must match after restart regardless of processing order")
}

func TestGlobalAffinityIDLeak(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)
	db := statedb.New()

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})
	extCfg := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: false}

	lbmaps := maps.NewFakeLBMaps()

	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)

	p := bpfOpsParams{
		Lifecycle:      lc,
		Log:            log,
		Config:         cfg,
		ExternalConfig: extCfg,
		LBMaps:         lbmaps,
		DB:             db,
		NodeAddresses:  nil,
		Frontends:      frontends,
	}

	ops := newBPFOps(p)

	svcName := loadbalancer.NewServiceName("leaksvc", "default")
	fe1 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.2"), 80, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: &loadbalancer.Service{
			Name:            svcName,
			SessionAffinity: true,
			Annotations: map[string]string{
				annotation.GlobalAffinity: "true",
			},
		},
	}
	fe2 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.2"), 443, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: fe1.Service,
	}

	fe1.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}
	fe2.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}

	wtxn := db.WriteTxn(frontends)
	_, _, err = frontends.Insert(wtxn, &fe1)
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, &fe2)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe1)
	require.NoError(t, err)
	
	wtxn = db.WriteTxn(frontends)
	cloned1 := fe1.Clone()
	_, _, err = frontends.Insert(wtxn, cloned1)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe2)
	require.NoError(t, err)
	
	wtxn = db.WriteTxn(frontends)
	cloned2 := fe2.Clone()
	_, _, err = frontends.Insert(wtxn, cloned2)
	require.NoError(t, err)
	wtxn.Commit()

	id1 := fe1.ID
	id2 := fe2.ID
	require.NotEqual(t, id1, id2)

	minID := id1
	if id2 < id1 {
		minID = id2
	}

	var feToDelete *loadbalancer.Frontend
	var feToKeep *loadbalancer.Frontend
	if fe1.ID == minID {
		feToDelete = &fe1
		feToKeep = &fe2
	} else {
		feToDelete = &fe2
		feToKeep = &fe1
	}

	// Delete primary first
	wtxn = db.WriteTxn(frontends)
	_, _, err = frontends.Delete(wtxn, feToDelete)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Delete(context.TODO(), db.ReadTxn(), 0, feToDelete)
	require.NoError(t, err)

	// Delete second
	wtxn = db.WriteTxn(frontends)
	_, _, err = frontends.Delete(wtxn, feToKeep)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Delete(context.TODO(), db.ReadTxn(), 0, feToKeep)
	require.NoError(t, err)

	// Verify both IDs are released in the allocator
	require.NotContains(t, ops.serviceIDAlloc.idToAddr, id1, "ID 1 leaked")
	require.NotContains(t, ops.serviceIDAlloc.idToAddr, id2, "ID 2 leaked")
}

func TestGlobalAffinityDeterminism(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)
	db := statedb.New()

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})
	extCfg := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: false}

	lbmaps := maps.NewFakeLBMaps()

	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)

	p := bpfOpsParams{
		Lifecycle:      lc,
		Log:            log,
		Config:         cfg,
		ExternalConfig: extCfg,
		LBMaps:         lbmaps,
		DB:             db,
		NodeAddresses:  nil,
		Frontends:      frontends,
	}

	ops := newBPFOps(p)

	svcName := loadbalancer.NewServiceName("detsvc", "default")
	fe1 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.3"), 80, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: &loadbalancer.Service{
			Name:            svcName,
			SessionAffinity: true,
			Annotations: map[string]string{
				annotation.GlobalAffinity: "true",
			},
		},
	}
	fe2 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.3"), 443, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: fe1.Service,
	}

	fe1.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}
	fe2.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}

	// Test order 1 then 2
	wtxn := db.WriteTxn(frontends)
	_, _, err = frontends.Insert(wtxn, &fe1)
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, &fe2)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe1)
	require.NoError(t, err)
	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe2)
	require.NoError(t, err)

	id1 := fe1.ID
	id2 := fe2.ID
	minID := id1
	if id2 < id1 {
		minID = id2
	}

	var aff1 uint16
	lbmaps.DumpGlobalAffinity(func(revNatID uint16, affinityID uint16, ipv6 bool) {
		if revNatID == uint16(id1) {
			aff1 = affinityID
		}
	})
	require.Equal(t, uint16(minID), aff1, "Order 1->2 failed to pick min ID")

	// Reset and test order 2 then 1
	ops2 := newBPFOps(p)
	
	wtxn = db.WriteTxn(frontends)
	_, _, err = frontends.Insert(wtxn, fe1.Clone())
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, fe2.Clone())
	require.NoError(t, err)
	wtxn.Commit()

	err = ops2.Update(context.TODO(), db.ReadTxn(), 0, &fe2)
	require.NoError(t, err)
	err = ops2.Update(context.TODO(), db.ReadTxn(), 0, &fe1)
	require.NoError(t, err)

	var aff2 uint16
	lbmaps.DumpGlobalAffinity(func(revNatID uint16, affinityID uint16, ipv6 bool) {
		if revNatID == uint16(id2) {
			aff2 = affinityID
		}
	})
	require.Equal(t, uint16(minID), aff2, "Order 2->1 failed to pick min ID")
}

func TestGlobalAffinityBPFFlag(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)
	db := statedb.New()

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})
	extCfg := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: false}

	lbmaps := maps.NewFakeLBMaps()

	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)

	p := bpfOpsParams{
		Lifecycle:      lc,
		Log:            log,
		Config:         cfg,
		ExternalConfig: extCfg,
		LBMaps:         lbmaps,
		DB:             db,
		NodeAddresses:  nil,
		Frontends:      frontends,
	}

	ops := newBPFOps(p)

	svcName := loadbalancer.NewServiceName("flagsvc", "default")
	fe1 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.4"), 80, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: &loadbalancer.Service{
			Name:            svcName,
			SessionAffinity: true,
			Annotations: map[string]string{
				annotation.GlobalAffinity: "true",
			},
		},
	}

	fe1.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}

	wtxn := db.WriteTxn(frontends)
	_, _, err = frontends.Insert(wtxn, &fe1)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe1)
	require.NoError(t, err)

	// Check flags in fake map
	var flags uint16
	lbmaps.DumpService(func(key maps.ServiceKey, value maps.ServiceValue) {
		kHost := key.ToHost()
		if kHost.GetPort() == 80 && kHost.GetAddress().String() == "10.0.2.4" {
			flags = value.GetFlags()
			t.Logf("TestGlobalAffinityBPFFlag: flags=0x%x, flags2=0x%x", flags, flags>>8)
		}
	})

	// SVC_FLAG_L7_LOADBALANCER is bit 2 in flags2.
	// In Go, SetFlags splits uint16 into Flags (lower) and Flags2 (upper).
	// So flags2 is flags >> 8.
	flags2 := uint8(flags >> 8)
	require.True(t, (flags2 & 0x04) != 0, "L7LoadBalancer flag not set for global affinity")

	// Now test without global affinity
	svcName2 := loadbalancer.NewServiceName("noflagsvc", "default")
	fe2 := loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svcName2,
			Address:     loadbalancer.NewL3n4Addr("TCP", types.MustParseAddrCluster("10.0.2.5"), 80, loadbalancer.ScopeExternal),
			Type:        ClusterIP,
		},
		Service: &loadbalancer.Service{
			Name:            svcName2,
			SessionAffinity: true,
		},
	}
	fe2.Backends = func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {}

	wtxn = db.WriteTxn(frontends)
	_, _, err = frontends.Insert(wtxn, &fe2)
	require.NoError(t, err)
	wtxn.Commit()

	err = ops.Update(context.TODO(), db.ReadTxn(), 0, &fe2)
	require.NoError(t, err)

	var flagsNoAff uint16
	lbmaps.DumpService(func(key maps.ServiceKey, value maps.ServiceValue) {
		if key.GetPort() == 80 && key.GetAddress().String() == "10.0.2.5" {
			flagsNoAff = value.GetFlags()
		}
	})
	flags2NoAff := uint8(flagsNoAff >> 8)
	require.False(t, (flags2NoAff & 0x04) != 0, "L7LoadBalancer flag set when it should not be")
}
