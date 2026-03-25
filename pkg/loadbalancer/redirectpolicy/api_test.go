// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"iter"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
)

const (
	testNamespaceKubeSystem       = "kube-system"
	testServiceNameKubeDNS        = "kube-dns"
	testPolicyNameNodeLocalDNS    = "nodelocaldns"
	testPodNameNodeLocalDNS       = "node-local-dns"
	testPodIDNodeLocalDNS         = testNamespaceKubeSystem + "/" + testPodNameNodeLocalDNS
	testPodLabelKeyK8sApp         = "k8s-app"
	testPodLabelValueNodeLocalDNS = "node-local-dns"
)

const (
	testServiceIP1         = "10.96.0.10"
	testAddressMatcherIPv4 = "169.254.20.10"
	testAddressMatcherIPv6 = "fd00:169:254::a"
	testNodePortIPv4       = "10.0.0.10"
	testPodIPv4            = "10.1.0.35"
	testPodIPv6            = "fd00:10:1::1cfc"
)

const (
	testPortNameDNSTCP = "dns-tcp"
	testPortNameDNSUDP = "dns"
	testDNSPortString  = "53"
	testDNSPort        = uint16(53)
)

var (
	testFEPortNameDNSTCP = lb.FEPortName(testPortNameDNSTCP)
	testFEPortNameDNSUDP = lb.FEPortName(testPortNameDNSUDP)
)

func newTestBackendsSeq(bes ...*lb.Backend) lb.BackendsSeq2 {
	return lb.BackendsSeq2(func(yield func(*lb.Backend, statedb.Revision) bool) {
		for _, be := range bes {
			if !yield(be, 0) {
				return
			}
		}
	})
}

func newTestFrontend(
	t *testing.T,
	ip string,
	port uint16,
	proto lb.L4Type,
	feType lb.SVCType,
	svcName lb.ServiceName,
	portName lb.FEPortName,
	redirectTo *lb.ServiceName,
	bes ...*lb.Backend,
) *lb.Frontend {
	t.Helper()

	return &lb.Frontend{
		FrontendParams: lb.FrontendParams{
			Address:     lb.NewL3n4Addr(proto, cmtypes.MustParseAddrCluster(ip), port, lb.ScopeExternal),
			Type:        feType,
			ServiceName: svcName,
			PortName:    portName,
			ServicePort: port,
		},
		Backends:   newTestBackendsSeq(bes...),
		RedirectTo: redirectTo,
	}
}

func newTestBackend(
	t *testing.T,
	svcName lb.ServiceName,
	ip string,
	port uint16,
	proto lb.L4Type,
	portName string,
) *lb.Backend {
	t.Helper()

	return newTestBackendWithPortNames(t, svcName, ip, port, proto, portName)
}

func newTestBackendWithPortNames(
	t *testing.T,
	svcName lb.ServiceName,
	ip string,
	port uint16,
	proto lb.L4Type,
	portNames ...string,
) *lb.Backend {
	t.Helper()

	be := &lb.Backend{
		ServiceName: svcName,
		Address:     lb.NewL3n4Addr(proto, cmtypes.MustParseAddrCluster(ip), port, lb.ScopeExternal),
		PortNames:   portNames,
		State:       lb.BackendStateActive,
	}
	be.SetSourcePriority(0)
	return be
}

func newTestReadyPod(t *testing.T) k8sTables.LocalPod {
	t.Helper()

	return k8sTables.LocalPod{
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      testPodNameNodeLocalDNS,
				Namespace: testNamespaceKubeSystem,
				Labels: map[string]string{
					testPodLabelKeyK8sApp: testPodLabelValueNodeLocalDNS,
				},
			},
			Spec: slim_corev1.PodSpec{
				Containers: []slim_corev1.Container{
					{
						Name: "node-cache",
						Ports: []slim_corev1.ContainerPort{
							{
								Name:          testPortNameDNSTCP,
								ContainerPort: int32(testDNSPort),
								Protocol:      slim_corev1.ProtocolTCP,
							},
							{
								Name:          testPortNameDNSUDP,
								ContainerPort: int32(testDNSPort),
								Protocol:      slim_corev1.ProtocolUDP,
							},
						},
					},
				},
			},
			Status: slim_corev1.PodStatus{
				Conditions: []slim_corev1.PodCondition{
					{Type: slim_corev1.PodReady, Status: slim_corev1.ConditionTrue},
				},
				PodIPs: []slim_corev1.PodIP{
					{IP: testPodIPv4},
					{IP: testPodIPv6},
				},
			},
		},
	}
}

func newTestNodeLocalDNSLRP(t *testing.T) *LocalRedirectPolicy {
	t.Helper()

	lrp, err := getSanitizedLocalRedirectPolicy(
		Config{},
		slog.Default(),
		testPolicyNameNodeLocalDNS,
		testNamespaceKubeSystem,
		k8sTypes.UID("test-uid"),
		v2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: v2.RedirectFrontend{
				ServiceMatcher: &v2.ServiceInfo{
					Name:      testServiceNameKubeDNS,
					Namespace: testNamespaceKubeSystem,
					ToPorts: []v2.PortInfo{
						{
							Port:     testDNSPortString,
							Name:     "tcp",
							Protocol: ciliumapi.ProtoTCP,
						},
						{
							Port:     testDNSPortString,
							Name:     "udp",
							Protocol: ciliumapi.ProtoUDP,
						},
					},
				},
			},
			RedirectBackend: v2.RedirectBackend{
				LocalEndpointSelector: slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						testPodLabelKeyK8sApp: testPodLabelValueNodeLocalDNS,
					},
				},
				ToPorts: []v2.PortInfo{
					{
						Port:     testDNSPortString,
						Name:     testPortNameDNSTCP,
						Protocol: ciliumapi.ProtoTCP,
					},
					{
						Port:     testDNSPortString,
						Name:     testPortNameDNSUDP,
						Protocol: ciliumapi.ProtoUDP,
					},
				},
			},
		},
	)
	require.NoError(t, err)
	return lrp
}

func newTestAddressLRP(t *testing.T) *LocalRedirectPolicy {
	t.Helper()

	return newTestAddressLRPWithPortInfo(t, testAddressMatcherIPv4,
		[]v2.PortInfo{
			{Port: testDNSPortString, Name: testPortNameDNSTCP, Protocol: ciliumapi.ProtoTCP},
			{Port: testDNSPortString, Name: testPortNameDNSUDP, Protocol: ciliumapi.ProtoUDP},
		},
		[]v2.PortInfo{
			{Port: testDNSPortString, Name: testPortNameDNSTCP, Protocol: ciliumapi.ProtoTCP},
			{Port: testDNSPortString, Name: testPortNameDNSUDP, Protocol: ciliumapi.ProtoUDP},
		},
	)
}

func newTestAddressLRPWithPortInfo(
	t *testing.T,
	frontendIP string,
	frontendPorts, backendPorts []v2.PortInfo,
) *LocalRedirectPolicy {
	t.Helper()

	lrp, err := getSanitizedLocalRedirectPolicy(
		Config{},
		slog.Default(),
		testPolicyNameNodeLocalDNS,
		testNamespaceKubeSystem,
		k8sTypes.UID("test-uid"),
		v2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: v2.RedirectFrontend{
				AddressMatcher: &v2.Frontend{
					IP:      frontendIP,
					ToPorts: frontendPorts,
				},
			},
			RedirectBackend: v2.RedirectBackend{
				LocalEndpointSelector: slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						testPodLabelKeyK8sApp: testPodLabelValueNodeLocalDNS,
					},
				},
				ToPorts: backendPorts,
			},
		},
	)
	require.NoError(t, err)
	return lrp
}

// TestGetModelServiceMatcherUsesResolvedFrontends expects serviceMatcher LRPs
// to render redirected ClusterIP frontends from the frontend table, with the
// protocol-specific backend subset already selected for each frontend, while
// ignoring internal placeholder addresses and non-ClusterIP frontends.
func TestGetModelServiceMatcherUsesResolvedFrontends(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()

	wtxn := db.WriteTxn(frontends, backends, pods)

	// Set up a matching node-local-dns pod selected by the LRP backend selector.
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)

	// Set up the pseudo-service backends that are resolved onto each frontend.
	insertBackend := func(ip string, port uint16, proto lb.L4Type, portName string) *lb.Backend {
		be := newTestBackend(t, lrp.RedirectServiceName(), ip, port, proto, portName)
		_, _, err = backends.Insert(wtxn, be)
		require.NoError(t, err)
		return be
	}
	tcpBackend := insertBackend(testPodIPv4, testDNSPort, lb.TCP, testPortNameDNSTCP)
	udpBackend := insertBackend(testPodIPv6, testDNSPort, lb.UDP, testPortNameDNSUDP)

	// Set up both ClusterIP and NodePort service frontends and verify that only
	// redirected ClusterIP frontends are returned by the API, each with the
	// backend subset selected by the LB writer.
	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testServiceIP1,
		testDNSPort,
		lb.TCP,
		lb.SVCTypeClusterIP,
		lrp.ServiceID,
		testFEPortNameDNSTCP,
		&lrpSvcName,
		tcpBackend,
	))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testServiceIP1,
		testDNSPort,
		lb.UDP,
		lb.SVCTypeClusterIP,
		lrp.ServiceID,
		testFEPortNameDNSUDP,
		&lrpSvcName,
		udpBackend,
	))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testNodePortIPv4,
		testDNSPort,
		lb.TCP,
		lb.SVCTypeNodePort,
		lrp.ServiceID,
		testFEPortNameDNSTCP,
		nil,
	))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testNodePortIPv4,
		testDNSPort,
		lb.UDP,
		lb.SVCTypeNodePort,
		lrp.ServiceID,
		testFEPortNameDNSUDP,
		nil,
	))
	require.NoError(t, err)

	// Commit all test objects before rendering the API model from StateDB.
	wtxn.Commit()

	// Render the API model and verify that only resolved ClusterIP frontends are shown.
	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 2)

	require.NotEmpty(t, lrp.FrontendMappings)
	internalFrontendIP := lrp.FrontendMappings[0].feAddr.AddrCluster().String()
	require.NotEqual(t, testServiceIP1, internalFrontendIP)

	gotByProtocol := map[string]*models.FrontendMapping{}
	for _, fe := range model.FrontendMappings {
		assert.Equal(t, testServiceIP1, fe.FrontendAddress.IP)
		assert.NotEqual(t, internalFrontendIP, fe.FrontendAddress.IP)
		assert.Equal(t, testDNSPort, fe.FrontendAddress.Port)
		gotByProtocol[fe.FrontendAddress.Protocol] = fe
	}
	assert.Contains(t, gotByProtocol, lb.TCP)
	assert.Contains(t, gotByProtocol, lb.UDP)

	tcpFrontend := gotByProtocol[lb.TCP]
	require.Len(t, tcpFrontend.Backends, 1)
	assert.Equal(t, testPodIDNodeLocalDNS, tcpFrontend.Backends[0].PodID)
	assert.Equal(t, testPodIPv4, *tcpFrontend.Backends[0].BackendAddress.IP)
	assert.Equal(t, testDNSPort, tcpFrontend.Backends[0].BackendAddress.Port)
	assert.Equal(t, lb.TCP, tcpFrontend.Backends[0].BackendAddress.Protocol)

	udpFrontend := gotByProtocol[lb.UDP]
	require.Len(t, udpFrontend.Backends, 1)
	assert.Equal(t, testPodIDNodeLocalDNS, udpFrontend.Backends[0].PodID)
	assert.Equal(t, testPodIPv6, *udpFrontend.Backends[0].BackendAddress.IP)
	assert.Equal(t, testDNSPort, udpFrontend.Backends[0].BackendAddress.Port)
	assert.Equal(t, lb.UDP, udpFrontend.Backends[0].BackendAddress.Protocol)

	for _, fe := range model.FrontendMappings {
		assert.NotEmpty(t, fe.FrontendAddress.IP)
		_, err := netip.ParseAddr(fe.FrontendAddress.IP)
		assert.NoError(t, err)
	}
}

// TestGetModelServiceMatcherWithoutRedirectedFrontend expects an unresolved
// serviceMatcher frontend to be hidden until it is redirected to the LRP
// pseudo-service.
func TestGetModelServiceMatcherWithoutRedirectedFrontend(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestNodeLocalDNSLRP(t)
	wtxn := db.WriteTxn(frontends)

	// Set up a matching service frontend that the controller has not redirected.
	_, _, err = frontends.Insert(wtxn, &lb.Frontend{
		FrontendParams: lb.FrontendParams{
			Address: lb.NewL3n4Addr(
				lb.TCP,
				cmtypes.MustParseAddrCluster(testServiceIP1),
				testDNSPort,
				lb.ScopeExternal,
			),
			Type:        lb.SVCTypeClusterIP,
			ServiceName: lrp.ServiceID,
			PortName:    testFEPortNameDNSTCP,
			ServicePort: testDNSPort,
		},
	})
	require.NoError(t, err)

	// Commit the frontend and verify that the API does not expose unresolved frontend state.
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	assert.Empty(t, model.FrontendMappings)
}

// TestGetModelServiceMatcherIncludesRedirectedFrontendWithoutBackends expects a
// redirected serviceMatcher frontend to be shown even when it has no selected
// backends.
func TestGetModelServiceMatcherIncludesRedirectedFrontendWithoutBackends(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()
	wtxn := db.WriteTxn(frontends)

	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testServiceIP1,
		testDNSPort,
		lb.TCP,
		lb.SVCTypeClusterIP,
		lrp.ServiceID,
		testFEPortNameDNSTCP,
		&lrpSvcName,
	))
	require.NoError(t, err)
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 1)
	assert.Empty(t, model.FrontendMappings[0].Backends)
	assert.Equal(t, testServiceIP1, model.FrontendMappings[0].FrontendAddress.IP)
}

// TestGetLRPsUsesFrontendTable expects the list API to render frontend
// mappings from the frontend table rather than the serviceMatcher policy's
// internal placeholder frontend addresses.
func TestGetLRPsUsesFrontendTable(t *testing.T) {
	db := statedb.New()
	lrps, err := NewLRPTable(db)
	require.NoError(t, err)
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()
	backend := newTestBackend(t, lrpSvcName, testPodIPv4, testDNSPort, lb.TCP, testPortNameDNSTCP)

	wtxn := db.WriteTxn(lrps, frontends, pods)
	_, _, err = lrps.Insert(wtxn, lrp)
	require.NoError(t, err)
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testServiceIP1,
		testDNSPort,
		lb.TCP,
		lb.SVCTypeClusterIP,
		lrp.ServiceID,
		testFEPortNameDNSTCP,
		&lrpSvcName,
		backend,
	))
	require.NoError(t, err)
	wtxn.Commit()

	models := getLRPs(db.ReadTxn(), lrps, frontends, backends, pods)
	require.Len(t, models, 1)
	require.Len(t, models[0].FrontendMappings, 1)
	assert.Equal(t, testServiceIP1, models[0].FrontendMappings[0].FrontendAddress.IP)
}

// TestGetBackendModelsIncludesBackendState expects backend state from StateDB
// to be carried into the API backend model.
func TestGetBackendModelsIncludesBackendState(t *testing.T) {
	backend := newTestBackend(t,
		lb.NewServiceName(testNamespaceKubeSystem, testServiceNameKubeDNS),
		testPodIPv4,
		testDNSPort,
		lb.TCP,
		testPortNameDNSTCP,
	)
	backend.State = lb.BackendStateTerminating
	expectedState, err := lb.BackendStateTerminating.String()
	require.NoError(t, err)

	backends := getBackendModels(
		map[string]string{testPodIPv4: testPodIDNodeLocalDNS},
		iter.Seq2[*lb.Backend, statedb.Revision](newTestBackendsSeq(backend)),
	)

	require.Len(t, backends, 1)
	assert.Equal(t, expectedState, backends[0].BackendAddress.State)
}

// TestGetModelAddressMatcherFiltersBackendsPerFrontend expects addressMatcher
// LRPs to render only the backends that match each frontend mapping by
// protocol, IP family, and named port when port names are present. Named port
// matching is case-insensitive, and unnamed backends remain eligible.
func TestGetModelAddressMatcherFiltersBackendsPerFrontend(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestAddressLRP(t)

	wtxn := db.WriteTxn(backends, pods)
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)

	const (
		tcpWrongFamilyPort  = uint16(54)
		tcpWrongNamePort    = uint16(55)
		tcpMultiNamePort    = uint16(56)
		tcpUnnamedPort      = uint16(57)
		tcpUpperNamePort    = uint16(58)
		portNameMetrics     = "metrics"
		portNameDNSTCPUpper = "DNS-TCP"
	)

	for _, be := range []*lb.Backend{
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, testDNSPort, lb.TCP, testPortNameDNSTCP),
		newTestBackend(
			t,
			lrp.RedirectServiceName(),
			testPodIPv6,
			tcpWrongFamilyPort,
			lb.TCP,
			testPortNameDNSTCP,
		),
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, tcpWrongNamePort, lb.TCP, portNameMetrics),
		newTestBackendWithPortNames(t,
			lrp.RedirectServiceName(),
			testPodIPv4,
			tcpMultiNamePort,
			lb.TCP,
			portNameMetrics,
			testPortNameDNSTCP,
		),
		newTestBackendWithPortNames(t, lrp.RedirectServiceName(), testPodIPv4, tcpUnnamedPort, lb.TCP),
		newTestBackend(
			t,
			lrp.RedirectServiceName(),
			testPodIPv4,
			tcpUpperNamePort,
			lb.TCP,
			portNameDNSTCPUpper,
		),
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, testDNSPort, lb.UDP, testPortNameDNSUDP),
	} {
		_, _, err = backends.Insert(wtxn, be)
		require.NoError(t, err)
	}
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 2)

	gotByProtocol := map[string]*models.FrontendMapping{}
	for _, fe := range model.FrontendMappings {
		assert.Equal(t, testAddressMatcherIPv4, fe.FrontendAddress.IP)
		assert.Equal(t, testDNSPort, fe.FrontendAddress.Port)
		gotByProtocol[fe.FrontendAddress.Protocol] = fe
	}

	assert.Contains(t, gotByProtocol, lb.TCP)
	assert.Contains(t, gotByProtocol, lb.UDP)

	tcpFrontend := gotByProtocol[lb.TCP]
	require.Len(t, tcpFrontend.Backends, 4)
	gotTCPPorts := map[uint16]struct{}{}
	for _, be := range tcpFrontend.Backends {
		assert.Equal(t, lb.TCP, be.BackendAddress.Protocol)
		assert.Equal(t, testPodIPv4, *be.BackendAddress.IP)
		gotTCPPorts[be.BackendAddress.Port] = struct{}{}
	}
	assert.Contains(t, gotTCPPorts, testDNSPort)
	assert.Contains(t, gotTCPPorts, tcpMultiNamePort)
	assert.Contains(t, gotTCPPorts, tcpUnnamedPort)
	assert.Contains(t, gotTCPPorts, tcpUpperNamePort)
	assert.NotContains(t, gotTCPPorts, tcpWrongFamilyPort)
	assert.NotContains(t, gotTCPPorts, tcpWrongNamePort)

	udpFrontend := gotByProtocol[lb.UDP]
	require.Len(t, udpFrontend.Backends, 1)
	assert.Equal(t, lb.UDP, udpFrontend.Backends[0].BackendAddress.Protocol)
	assert.Equal(t, testPodIPv4, *udpFrontend.Backends[0].BackendAddress.IP)
}

// TestGetModelAddressMatcherMapsNamedPortsWithDifferentBackendPorts expects
// named addressMatcher frontends to match backends by port name, protocol, and
// frontend port, not by equal frontend/backend port numbers.
func TestGetModelAddressMatcherMapsNamedPortsWithDifferentBackendPorts(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	const (
		portNameHTTP          = "http"
		portNameMetrics       = "metrics"
		portHTTPString        = "80"
		portHTTP              = uint16(80)
		backendPortHTTPString = "8080"
		backendPortHTTP       = uint16(8080)
		backendPortDNSString  = "5353"
		backendPortDNS        = uint16(5353)
		portMetrics           = uint16(9090)
	)

	lrp := newTestAddressLRPWithPortInfo(t, testAddressMatcherIPv4,
		[]v2.PortInfo{
			{Port: portHTTPString, Name: portNameHTTP, Protocol: ciliumapi.ProtoTCP},
			{Port: testDNSPortString, Name: testPortNameDNSUDP, Protocol: ciliumapi.ProtoUDP},
		},
		[]v2.PortInfo{
			{Port: backendPortHTTPString, Name: portNameHTTP, Protocol: ciliumapi.ProtoTCP},
			{Port: backendPortDNSString, Name: testPortNameDNSUDP, Protocol: ciliumapi.ProtoUDP},
		},
	)

	wtxn := db.WriteTxn(backends, pods)
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)

	for _, be := range []*lb.Backend{
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, backendPortHTTP, lb.TCP, portNameHTTP),
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, portMetrics, lb.TCP, portNameMetrics),
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, backendPortDNS, lb.UDP, testPortNameDNSUDP),
		newTestBackend(t, lrp.RedirectServiceName(), testPodIPv4, backendPortDNS, lb.TCP, testPortNameDNSUDP),
	} {
		_, _, err = backends.Insert(wtxn, be)
		require.NoError(t, err)
	}
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 2)

	gotByProtocol := map[string]*models.FrontendMapping{}
	for _, fe := range model.FrontendMappings {
		gotByProtocol[fe.FrontendAddress.Protocol] = fe
	}

	tcpFrontend := gotByProtocol[lb.TCP]
	require.NotNil(t, tcpFrontend)
	assert.Equal(t, portHTTP, tcpFrontend.FrontendAddress.Port)
	require.Len(t, tcpFrontend.Backends, 1)
	assert.Equal(t, backendPortHTTP, tcpFrontend.Backends[0].BackendAddress.Port)
	assert.Equal(t, lb.TCP, tcpFrontend.Backends[0].BackendAddress.Protocol)

	udpFrontend := gotByProtocol[lb.UDP]
	require.NotNil(t, udpFrontend)
	assert.Equal(t, testDNSPort, udpFrontend.FrontendAddress.Port)
	require.Len(t, udpFrontend.Backends, 1)
	assert.Equal(t, backendPortDNS, udpFrontend.Backends[0].BackendAddress.Port)
	assert.Equal(t, lb.UDP, udpFrontend.Backends[0].BackendAddress.Protocol)
}

// TestGetModelAddressMatcherFiltersBackendsByIPFamily expects addressMatcher
// frontends to include only backends from the same IP family.
func TestGetModelAddressMatcherFiltersBackendsByIPFamily(t *testing.T) {
	testCases := []struct {
		name       string
		frontendIP string
		wantIP     string
	}{
		{
			name:       "IPv4 frontend",
			frontendIP: testAddressMatcherIPv4,
			wantIP:     testPodIPv4,
		},
		{
			name:       "IPv6 frontend",
			frontendIP: testAddressMatcherIPv6,
			wantIP:     testPodIPv6,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			db := statedb.New()
			frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
			require.NoError(t, err)
			backends, err := lb.NewBackendsTable(db)
			require.NoError(t, err)
			pods, err := k8sTables.NewPodTable(db)
			require.NoError(t, err)

			lrp := newTestAddressLRPWithPortInfo(t, tt.frontendIP,
				[]v2.PortInfo{
					{
						Port:     testDNSPortString,
						Name:     testPortNameDNSTCP,
						Protocol: ciliumapi.ProtoTCP,
					},
				},
				[]v2.PortInfo{
					{
						Port:     testDNSPortString,
						Name:     testPortNameDNSTCP,
						Protocol: ciliumapi.ProtoTCP,
					},
				},
			)

			wtxn := db.WriteTxn(backends, pods)
			_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
			require.NoError(t, err)
			_, _, err = backends.Insert(wtxn, newTestBackend(t,
				lrp.RedirectServiceName(),
				testPodIPv4,
				testDNSPort,
				lb.TCP,
				testPortNameDNSTCP,
			))
			require.NoError(t, err)
			_, _, err = backends.Insert(wtxn, newTestBackend(t,
				lrp.RedirectServiceName(),
				testPodIPv6,
				testDNSPort,
				lb.TCP,
				testPortNameDNSTCP,
			))
			require.NoError(t, err)
			wtxn.Commit()

			model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
			require.NotNil(t, model)
			require.Len(t, model.FrontendMappings, 1)
			require.Len(t, model.FrontendMappings[0].Backends, 1)
			assert.Equal(t, tt.frontendIP, model.FrontendMappings[0].FrontendAddress.IP)
			assert.Equal(t, tt.wantIP, *model.FrontendMappings[0].Backends[0].BackendAddress.IP)
		})
	}
}

// TestGetModelAddressMatcherUsesPreferredBackendByAddress expects duplicate
// backend instances for the same address to collapse to the preferred source
// priority before the API model is rendered.
func TestGetModelAddressMatcherUsesPreferredBackendByAddress(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestAddressLRPWithPortInfo(t, testAddressMatcherIPv4,
		[]v2.PortInfo{
			{Port: testDNSPortString, Name: testPortNameDNSTCP, Protocol: ciliumapi.ProtoTCP},
		},
		[]v2.PortInfo{
			{Port: testDNSPortString, Name: testPortNameDNSTCP, Protocol: ciliumapi.ProtoTCP},
		},
	)

	preferredBackend := newTestBackend(t,
		lrp.RedirectServiceName(),
		testPodIPv4,
		testDNSPort,
		lb.TCP,
		testPortNameDNSTCP,
	)
	preferredBackend.State = lb.BackendStateTerminating
	preferredBackend.SetSourcePriority(0)

	lowerPriorityBackend := newTestBackend(t,
		lrp.RedirectServiceName(),
		testPodIPv4,
		testDNSPort,
		lb.TCP,
		testPortNameDNSTCP,
	)
	lowerPriorityBackend.State = lb.BackendStateActive
	lowerPriorityBackend.SetSourcePriority(10)

	wtxn := db.WriteTxn(backends, pods)
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)
	_, _, err = backends.Insert(wtxn, lowerPriorityBackend)
	require.NoError(t, err)
	_, _, err = backends.Insert(wtxn, preferredBackend)
	require.NoError(t, err)
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 1)
	require.Len(t, model.FrontendMappings[0].Backends, 1)

	expectedState, err := lb.BackendStateTerminating.String()
	require.NoError(t, err)
	assert.Equal(t, expectedState, model.FrontendMappings[0].Backends[0].BackendAddress.State)
}

// TestGetModelServiceMatcherFiltersUnredirectedFrontends expects serviceMatcher
// LRPs to render only ClusterIP frontends redirected to this LRP, excluding
// unredirected frontends, frontends redirected elsewhere, and non-ClusterIP
// frontends.
func TestGetModelServiceMatcherFiltersUnredirectedFrontends(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := newTestNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()
	otherSvcName := lb.NewServiceName(testNamespaceKubeSystem, "other-local-redirect")
	matchingBackend := newTestBackend(t, lrpSvcName, testPodIPv4, testDNSPort, lb.TCP, testPortNameDNSTCP)

	wtxn := db.WriteTxn(frontends, pods)
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)

	testCases := []struct {
		name       string
		frontendIP string
		svcType    lb.SVCType
		redirectTo *lb.ServiceName
	}{
		{
			name:       "included ClusterIP redirected to LRP",
			frontendIP: testServiceIP1,
			svcType:    lb.SVCTypeClusterIP,
			redirectTo: &lrpSvcName,
		},
		{
			name:       "excluded ClusterIP without redirect",
			frontendIP: "10.96.0.11",
			svcType:    lb.SVCTypeClusterIP,
		},
		{
			name:       "excluded ClusterIP redirected elsewhere",
			frontendIP: "10.96.0.12",
			svcType:    lb.SVCTypeClusterIP,
			redirectTo: &otherSvcName,
		},
		{
			name:       "excluded NodePort redirected to LRP",
			frontendIP: testNodePortIPv4,
			svcType:    lb.SVCTypeNodePort,
			redirectTo: &lrpSvcName,
		},
	}

	for _, tt := range testCases {
		_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
			tt.frontendIP,
			testDNSPort,
			lb.TCP,
			tt.svcType,
			lrp.ServiceID,
			testFEPortNameDNSTCP,
			tt.redirectTo,
			matchingBackend,
		))
		require.NoError(t, err, tt.name)
	}
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 1)
	assert.Equal(t, testServiceIP1, model.FrontendMappings[0].FrontendAddress.IP)
}

// TestGetModelServiceMatcherUnknownPodBackend expects backend IPs that cannot
// be mapped to a local pod to render with an "unknown" PodID.
func TestGetModelServiceMatcherUnknownPodBackend(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	const unknownPodIPv4 = "10.1.0.99"

	lrp := newTestNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()
	unknownPodBackend := newTestBackend(t, lrpSvcName, unknownPodIPv4, testDNSPort, lb.TCP, testPortNameDNSTCP)

	wtxn := db.WriteTxn(frontends, pods)
	_, _, err = pods.Insert(wtxn, newTestReadyPod(t))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, newTestFrontend(t,
		testServiceIP1,
		testDNSPort,
		lb.TCP,
		lb.SVCTypeClusterIP,
		lrp.ServiceID,
		testFEPortNameDNSTCP,
		&lrpSvcName,
		unknownPodBackend,
	))
	require.NoError(t, err)
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 1)
	require.Len(t, model.FrontendMappings[0].Backends, 1)
	assert.Equal(t, "unknown", model.FrontendMappings[0].Backends[0].PodID)
	assert.Equal(t, unknownPodIPv4, *model.FrontendMappings[0].Backends[0].BackendAddress.IP)
}
