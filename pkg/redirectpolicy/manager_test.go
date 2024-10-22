// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
)

type ManagerSuite struct {
	rpm *Manager
	svc svcManager
	epM endpointManager
}

func setupManagerSuite(tb testing.TB) *ManagerSuite {
	testutils.PrivilegedTest(tb)

	m := &ManagerSuite{}
	m.svc = &fakeSvcManager{}
	fpr := &fakePodResource{
		fakePodStore{},
	}
	m.epM = &fakeEpManager{}
	m.rpm = NewRedirectPolicyManager(m.svc, nil, fpr, m.epM)
	configAddrType = LRPConfig{
		id: k8s.ServiceID{
			Name:      "test-foo",
			Namespace: "ns1",
		},
		lrpType:      lrpConfigTypeAddr,
		frontendType: addrFrontendSinglePort,
		frontendMappings: []*feMapping{{
			feAddr:      fe1,
			podBackends: nil,
			fePort:      portName1,
		}},
		backendSelector: api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"test": "foo",
				},
			},
		},
		backendPorts: []bePortInfo{beP1},
	}
	configSvcType = LRPConfig{
		id: k8s.ServiceID{
			Name:      "test-foo",
			Namespace: "ns1",
		},
		lrpType: lrpConfigTypeSvc,
		backendSelector: api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"test": "foo",
				},
			},
		},
	}

	return m
}

type fakeSvcManager struct {
	upsertEvents            chan *lb.SVC
	destroyConnectionEvents chan lb.L3n4Addr
}

func (f *fakeSvcManager) DeleteService(lb.L3n4Addr) (bool, error) {
	return true, nil
}

func (f *fakeSvcManager) UpsertService(s *lb.SVC) (bool, lb.ID, error) {
	if f.upsertEvents != nil {
		f.upsertEvents <- s
	}
	return true, 1, nil
}

func (f *fakeSvcManager) TerminateUDPConnectionsToBackend(l3n4Addr *lb.L3n4Addr) {
	if f.destroyConnectionEvents != nil {
		f.destroyConnectionEvents <- *l3n4Addr
	}
}

type fakePodResource struct {
	store fakePodStore
}

func (fpr *fakePodResource) Observe(ctx context.Context, next func(resource.Event[*slimcorev1.Pod]), complete func(error)) {
	panic("unimplemented")
}
func (fpr *fakePodResource) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*slimcorev1.Pod] {
	panic("unimplemented")
}
func (fpr *fakePodResource) Store(context.Context) (resource.Store[*slimcorev1.Pod], error) {
	return &fpr.store, nil
}

type fakePodStore struct {
	OnList func() []*slimcorev1.Pod
	Pods   map[resource.Key]*slimcorev1.Pod
}

func (ps *fakePodStore) List() []*slimcorev1.Pod {
	if ps.OnList != nil {
		return ps.OnList()
	}
	pods := []*slimcorev1.Pod{pod1, pod2}
	return pods
}

func (ps *fakePodStore) IterKeys() resource.KeyIter { return nil }
func (ps *fakePodStore) Get(obj *slimcorev1.Pod) (item *slimcorev1.Pod, exists bool, err error) {
	return nil, false, nil
}
func (ps *fakePodStore) GetByKey(key resource.Key) (item *slimcorev1.Pod, exists bool, err error) {
	if len(ps.Pods) != 0 {
		return ps.Pods[key], true, nil
	}
	return nil, false, nil
}
func (ps *fakePodStore) CacheStore() cache.Store { return nil }

func (ps *fakePodStore) IndexKeys(indexName, indexedValue string) ([]string, error) { return nil, nil }
func (ps *fakePodStore) ByIndex(indexName, indexedValue string) ([]*slimcorev1.Pod, error) {
	return nil, nil
}
func (ps *fakePodStore) Release() {
}

type fakeEpManager struct {
	cookies map[netip.Addr]uint64
}

func (ps *fakeEpManager) Subscribe(s endpointmanager.Subscriber) {
}

func (ps *fakeEpManager) GetEndpointNetnsCookieByIP(ip netip.Addr) (uint64, error) {
	c, ok := ps.cookies[ip]
	if !ok {
		return 0, fmt.Errorf("endpoint not found")
	}
	return c, nil
}

type fakeSkipLBMap struct {
	lb4Events chan skipLBParams
	lb6Events chan skipLBParams
}

type skipLBParams struct {
	cookie uint64
	ip     net.IP
	port   uint16
}

func (f fakeSkipLBMap) AddLB4(netnsCookie uint64, ip net.IP, port uint16) error {
	f.lb4Events <- skipLBParams{
		cookie: netnsCookie,
		ip:     ip,
		port:   port,
	}

	return nil
}

func (f fakeSkipLBMap) AddLB6(netnsCookie uint64, ip net.IP, port uint16) error {
	f.lb6Events <- skipLBParams{
		cookie: netnsCookie,
		ip:     ip,
		port:   port,
	}

	return nil
}

func (f fakeSkipLBMap) DeleteLB4ByAddrPort(ip net.IP, port uint16) {
	panic("implement me")
}

func (f fakeSkipLBMap) DeleteLB6ByAddrPort(ip net.IP, port uint16) {
	panic("implement me")
}

func (f fakeSkipLBMap) DeleteLB4ByNetnsCookie(cookie uint64) {
	panic("implement me")
}

func (f fakeSkipLBMap) DeleteLB6ByNetnsCookie(cookie uint64) {
	panic("implement me")
}

var (
	tcpStr    = "TCP"
	udpStr    = "UDP"
	proto1, _ = lb.NewL4Type(tcpStr)
	proto2, _ = lb.NewL4Type(udpStr)
	fe1       = lb.NewL3n4Addr(
		proto1,
		cmtypes.MustParseAddrCluster("1.1.1.1"),
		80,
		lb.ScopeExternal)
	fe2 = lb.NewL3n4Addr(
		proto2,
		cmtypes.MustParseAddrCluster("2.2.2.2"),
		81,
		lb.ScopeExternal)
	fe3v6 = lb.NewL3n4Addr(
		proto1,
		cmtypes.MustParseAddrCluster("fd00::2"),
		80,
		lb.ScopeExternal)
	portName1 = "test1"
	portName2 = "test2"
	beP1      = bePortInfo{
		l4Addr: lb.L4Addr{
			Protocol: tcpStr,
			Port:     8080,
		},
		name: portName1,
	}
	beP2 = bePortInfo{
		l4Addr: lb.L4Addr{
			Protocol: udpStr,
			Port:     8081,
		},
		name: portName2,
	}
	configAddrType LRPConfig
	configSvcType  LRPConfig

	podReady = slimcorev1.PodCondition{
		Type:               slimcorev1.PodReady,
		Status:             slimcorev1.ConditionTrue,
		LastProbeTime:      slim_metav1.Now(),
		LastTransitionTime: slim_metav1.Now(),
		Reason:             "",
		Message:            "",
	}

	podNotReady = slimcorev1.PodCondition{
		Type:               slimcorev1.PodReady,
		Status:             slimcorev1.ConditionTrue,
		LastProbeTime:      slim_metav1.Now(),
		LastTransitionTime: slim_metav1.Now(),
		Reason:             "",
		Message:            "",
	}

	pod1IP1    = slimcorev1.PodIP{IP: "1.2.3.4"}
	pod1IP2    = slimcorev1.PodIP{IP: "5.6.7.8"}
	pod1Port1  = int32(8080)
	pod1Port2  = int32(8081)
	pod1Proto1 = slimcorev1.ProtocolTCP
	pod1Proto2 = slimcorev1.ProtocolUDP
	pod1       = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-be",
			Namespace: "ns1",
			Labels:    map[string]string{"test": "foo"},
		},
		Spec: slimcorev1.PodSpec{
			Containers: []slimcorev1.Container{
				{
					Ports: []slimcorev1.ContainerPort{
						{
							Name:          portName1,
							ContainerPort: pod1Port1,
							Protocol:      pod1Proto1,
						},
						{
							Name:          portName2,
							ContainerPort: pod1Port2,
							Protocol:      pod1Proto2,
						},
					},
				},
			},
		},
		Status: slimcorev1.PodStatus{
			PodIP:      pod1IP1.IP,
			PodIPs:     []slimcorev1.PodIP{pod1IP1, pod1IP2},
			Conditions: []slimcorev1.PodCondition{podReady},
		},
	}
	pod1ID = k8s.ServiceID{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
	}
	pod2IP1    = slimcorev1.PodIP{IP: "5.6.7.9"}
	pod2IP2    = slimcorev1.PodIP{IP: "5.6.7.10"}
	pod2Port1  = int32(8080)
	pod2Port2  = int32(8081)
	pod2Proto1 = slimcorev1.ProtocolTCP
	pod2Proto2 = slimcorev1.ProtocolUDP
	pod2       = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-be2",
			Namespace: "ns1",
			Labels:    map[string]string{"test": "bar"},
		},
		Spec: slimcorev1.PodSpec{
			Containers: []slimcorev1.Container{
				{
					Ports: []slimcorev1.ContainerPort{
						{
							Name:          portName1,
							ContainerPort: pod2Port1,
							Protocol:      pod2Proto1,
						},
						{
							Name:          portName2,
							ContainerPort: pod2Port2,
							Protocol:      pod2Proto2,
						},
					},
				},
			},
		},
		Status: slimcorev1.PodStatus{
			PodIP:      pod2IP1.IP,
			PodIPs:     []slimcorev1.PodIP{pod2IP1, pod2IP2},
			Conditions: []slimcorev1.PodCondition{podReady},
		},
	}
	pod2ID = k8s.ServiceID{
		Name:      pod2.Name,
		Namespace: pod2.Namespace,
	}
)

// Tests if duplicate addressMatcher configs are not added.
func TestManager_AddRedirectPolicy_AddrMatcherDuplicateConfig(t *testing.T) {
	m := setupManagerSuite(t)

	configFe := configAddrType
	m.rpm.policyFrontendsByHash[fe1.Hash()] = configFe.id
	dupConfigFe := configFe
	dupConfigFe.id.Name = "test-foo2"

	added, err := m.rpm.AddRedirectPolicy(dupConfigFe)

	require.Equal(t, false, added)
	require.Error(t, err)
}

// Tests if duplicate svcMatcher configs are not added.
func TestManager_AddRedirectPolicy_SvcMatcherDuplicateConfig(t *testing.T) {
	m := setupManagerSuite(t)

	configSvc := configSvcType
	configSvc.serviceID = &k8s.ServiceID{
		Name:      "foo",
		Namespace: "ns1",
	}
	m.rpm.policyConfigs[configSvc.id] = &configSvc
	m.rpm.policyServices[*configSvc.serviceID] = configSvc.id
	invalidConfigSvc := configSvc
	invalidConfigSvc.id.Name = "test-foo3"

	added, err := m.rpm.AddRedirectPolicy(invalidConfigSvc)

	require.Equal(t, false, added)
	require.Error(t, err)
}

// Tests add redirect policy, add pod, delete pod and delete redirect policy events
// for an addressMatcher config with a frontend having single port.
func TestManager_AddrMatcherConfigSinglePort(t *testing.T) {
	m := setupManagerSuite(t)

	// Add an addressMatcher type LRP with single port. The policy config
	// frontend should have 2 pod backends with each of the podIPs.
	podIPs := utils.ValidIPs(pod1.Status)
	expectedbes := make([]backend, len(podIPs))
	for i := range podIPs {
		expectedbes[i] = backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP1.l4Addr},
			podID:    pod1ID,
		}
	}

	added, err := m.rpm.AddRedirectPolicy(configAddrType)

	require.Equal(t, true, added)
	require.Nil(t, err)
	require.Equal(t, 1, len(m.rpm.policyConfigs))
	require.Equal(t, configAddrType.id.Name, m.rpm.policyConfigs[configAddrType.id].id.Name)
	require.Equal(t, configAddrType.id.Namespace, m.rpm.policyConfigs[configAddrType.id].id.Namespace)
	require.Equal(t, 1, len(m.rpm.policyFrontendsByHash))
	require.Equal(t, configAddrType.id, m.rpm.policyFrontendsByHash[configAddrType.frontendMappings[0].feAddr.Hash()])
	require.Equal(t, 2, len(configAddrType.frontendMappings[0].podBackends))
	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes[i], configAddrType.frontendMappings[0].podBackends[i])
	}
	require.Equal(t, 1, len(m.rpm.policyPods))
	require.Equal(t, 1, len(m.rpm.policyPods[pod1ID]))
	require.Equal(t, configAddrType.id, m.rpm.policyPods[pod1ID][0])

	// Add a new backend pod, this will add 2 more pod backends with each of the podIPs.
	pod3 := pod2.DeepCopy()
	pod3.Labels["test"] = "foo"
	pod3ID := pod2ID
	podIPs = utils.ValidIPs(pod3.Status)
	expectedbes2 := make([]backend, 0, len(expectedbes)+len(podIPs))
	expectedbes2 = append(expectedbes2, expectedbes...)
	for i := range podIPs {
		expectedbes2 = append(expectedbes2, backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP1.l4Addr},
			podID:    pod3ID,
		})
	}

	m.rpm.OnAddPod(pod3)

	require.Equal(t, 2, len(m.rpm.policyPods))
	require.Equal(t, 1, len(m.rpm.policyPods[pod3ID]))
	require.Equal(t, configAddrType.id, m.rpm.policyPods[pod1ID][0])
	require.Equal(t, 4, len(configAddrType.frontendMappings[0].podBackends))
	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes2[i], configAddrType.frontendMappings[0].podBackends[i])
	}

	// When pod becomes un-ready
	pod3.Status.Conditions = []slimcorev1.PodCondition{podNotReady}
	m.rpm.OnUpdatePod(pod3, false, false)

	require.Equal(t, 2, len(m.rpm.policyPods))
	require.Equal(t, 1, len(m.rpm.policyPods[pod3ID]))
	require.Equal(t, 2, len(configAddrType.frontendMappings[0].podBackends))
	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes[i], configAddrType.frontendMappings[0].podBackends[i])
	}

	// When pod becomes ready
	pod3.Status.Conditions = []slimcorev1.PodCondition{podReady}
	m.rpm.OnUpdatePod(pod3, false, true)

	require.Equal(t, 2, len(m.rpm.policyPods))
	require.Equal(t, 1, len(m.rpm.policyPods[pod3ID]))
	require.Equal(t, configAddrType.id, m.rpm.policyPods[pod1ID][0])
	require.Equal(t, 4, len(configAddrType.frontendMappings[0].podBackends))
	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes2[i], configAddrType.frontendMappings[0].podBackends[i])
	}

	// Delete the pod. This should delete the pod's backends.
	m.rpm.OnDeletePod(pod3)

	require.Equal(t, 1, len(m.rpm.policyPods))
	_, found := m.rpm.policyPods[pod3ID]
	require.Equal(t, false, found)
	require.Equal(t, 2, len(configAddrType.frontendMappings[0].podBackends))
	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes[i], configAddrType.frontendMappings[0].podBackends[i])
	}

	// Delete the LRP.
	err = m.rpm.DeleteRedirectPolicy(configAddrType)

	require.Nil(t, err)
	require.Equal(t, 0, len(m.rpm.policyFrontendsByHash))
	require.Equal(t, 0, len(m.rpm.policyPods))
	require.Equal(t, 0, len(m.rpm.policyConfigs))
}

// Tests add redirect policy, add pod, delete pod and delete redirect policy events
// for an addressMatcher config with a frontend having multiple named ports.
func TestManager_AddrMatcherConfigMultiplePorts(t *testing.T) {
	m := setupManagerSuite(t)

	// Add an addressMatcher type LRP with multiple named ports.
	configAddrType.frontendType = addrFrontendNamedPorts
	configAddrType.frontendMappings = append(configAddrType.frontendMappings, &feMapping{
		feAddr:      fe2,
		podBackends: nil,
		fePort:      portName2,
	})
	beP1.name = portName1
	beP2.name = portName2
	configAddrType.backendPorts = []bePortInfo{beP1, beP2}
	configAddrType.backendPortsByPortName = map[string]*bePortInfo{
		beP1.name: &configAddrType.backendPorts[0],
		beP2.name: &configAddrType.backendPorts[1]}
	podIPs := utils.ValidIPs(pod1.Status)
	expectedbes := make([]backend, 0, len(podIPs))
	for i := range podIPs {
		expectedbes = append(expectedbes, backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP1.l4Addr},
			podID:    pod1ID,
		})
	}

	added, err := m.rpm.AddRedirectPolicy(configAddrType)

	require.Equal(t, true, added)
	require.Nil(t, err)
	require.Equal(t, 1, len(m.rpm.policyConfigs))
	require.Equal(t, configAddrType.id.Name, m.rpm.policyConfigs[configAddrType.id].id.Name)
	require.Equal(t, configAddrType.id.Namespace, m.rpm.policyConfigs[configAddrType.id].id.Namespace)
	require.Equal(t, 2, len(m.rpm.policyFrontendsByHash))
	for _, id := range m.rpm.policyFrontendsByHash {
		require.Equal(t, configAddrType.id, id)
	}
	// Frontend ports should be mapped to the corresponding backend ports.
	for _, feM := range configAddrType.frontendMappings {
		switch feM.fePort {
		case "test1":
			require.Equal(t, 2, len(feM.podBackends))
			for i := range podIPs {
				expectedbes[i] = backend{
					L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP1.l4Addr},
					podID:    pod1ID,
				}
			}
			for i := range feM.podBackends {
				require.Equal(t, expectedbes[i], feM.podBackends[i])
			}
		case "test2":
			require.Equal(t, 2, len(feM.podBackends))
			for i := range podIPs {
				expectedbes[i] = backend{
					L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP2.l4Addr},
					podID:    pod1ID,
				}
			}
			for i := range feM.podBackends {
				require.Equal(t, expectedbes[i], feM.podBackends[i])
			}
		default:
			log.Errorf("Unknown port %s", feM.fePort)
		}
	}
	require.Equal(t, 1, len(m.rpm.policyPods))
	require.Equal(t, 1, len(m.rpm.policyPods[pod1ID]))
	require.Equal(t, configAddrType.id, m.rpm.policyPods[pod1ID][0])

	// Delete the LRP.
	err = m.rpm.DeleteRedirectPolicy(configAddrType)

	require.Nil(t, err)
	require.Equal(t, 0, len(m.rpm.policyFrontendsByHash))
	require.Equal(t, 0, len(m.rpm.policyPods))
	require.Equal(t, 0, len(m.rpm.policyConfigs))
}

// Tests if frontend ipv4 and ipv6 addresses are mapped to the ipv4 and ipv6
// backends, respectively.
func TestManager_AddrMatcherConfigDualStack(t *testing.T) {
	m := setupManagerSuite(t)

	// Only ipv4 backend(s) for ipv4 frontend
	pod3 := pod1.DeepCopy()
	pod3ID := pod1ID
	podIPs := utils.ValidIPs(pod3.Status)
	expectedbes4 := make([]backend, 0, len(podIPs))
	for i := range podIPs {
		expectedbes4 = append(expectedbes4, backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP1.l4Addr},
			podID:    pod3ID,
		})
	}
	pod3v6 := slimcorev1.PodIP{IP: "fd00::40"}
	expectedbes6 := []backend{{
		L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(pod3v6.IP), L4Addr: beP1.l4Addr},
		podID:    pod3ID,
	}}
	pod3.Status.PodIPs = append(pod3.Status.PodIPs, pod3v6)
	psg := &fakePodResource{
		fakePodStore{
			OnList: func() []*slimcorev1.Pod {
				return []*slimcorev1.Pod{pod3}
			},
		},
	}
	m.rpm.localPods = psg

	added, err := m.rpm.AddRedirectPolicy(configAddrType)

	require.Equal(t, true, added)
	require.Nil(t, err)
	require.Equal(t, len(expectedbes4), len(configAddrType.frontendMappings[0].podBackends))
	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes4[i], configAddrType.frontendMappings[0].podBackends[i])
	}

	// Only ipv6 backend(s) for ipv6 frontend
	feM := []*feMapping{{
		feAddr:      fe3v6,
		podBackends: nil,
	}}
	configAddrType.id.Name = "test-bar"
	configAddrType.frontendMappings = feM

	added, err = m.rpm.AddRedirectPolicy(configAddrType)

	require.Equal(t, true, added)
	require.Nil(t, err)
	require.Equal(t, len(expectedbes6), len(configAddrType.frontendMappings[0].podBackends))

	for i := range configAddrType.frontendMappings[0].podBackends {
		require.Equal(t, expectedbes6[i], configAddrType.frontendMappings[0].podBackends[i])
	}
}

// Tests add and update pod operations with namespace mismatched pods.
func TestManager_OnAddandUpdatePod(t *testing.T) {
	m := setupManagerSuite(t)

	configFe := configAddrType
	m.rpm.policyFrontendsByHash[fe1.Hash()] = configFe.id
	configSvc := configSvcType
	m.rpm.policyConfigs[configSvc.id] = &configSvc
	pod := pod1.DeepCopy()
	pod.Namespace = "ns2"
	podID := k8s.ServiceID{
		Name:      pod.Name,
		Namespace: pod.Namespace,
	}

	m.rpm.OnAddPod(pod)

	// Namespace mismatched pod not selected.
	require.Equal(t, 0, len(m.rpm.policyPods))
	_, found := m.rpm.policyPods[podID]
	require.Equal(t, false, found)

	m.rpm.OnUpdatePod(pod, true, true)

	// Namespace mismatched pod not selected.
	require.Equal(t, 0, len(m.rpm.policyPods))
	_, found = m.rpm.policyPods[podID]
	require.Equal(t, false, found)
}

// Tests policies with skipRedirectFromBackend flag set.
func TestManager_OnAddRedirectPolicy(t *testing.T) {
	m := setupManagerSuite(t)

	// Sequence of events: Pods -> RedirectPolicy -> Endpoint
	sMgr := &fakeSvcManager{}
	sMgr.upsertEvents = make(chan *lb.SVC)
	m.svc = sMgr
	lbEvents := make(chan skipLBParams)
	pc := configAddrType
	pc.skipRedirectFromBackend = true
	pods := make(map[resource.Key]*slimcorev1.Pod)
	pk1 := resource.Key{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
	}
	pod := pod1.DeepCopy()
	pod.Status.PodIPs = []slimcorev1.PodIP{pod1IP1}
	pods[pk1] = pod
	fps := &fakePodResource{
		fakePodStore{
			Pods: pods,
		},
	}
	m.rpm.localPods = fps
	ep := &endpoint.Endpoint{
		K8sPodName:   pod.Name,
		K8sNamespace: pod.Namespace,
		NetNsCookie:  1234,
	}
	m.rpm = NewRedirectPolicyManager(m.svc, nil, fps, m.epM)
	m.rpm.skipLBMap = &fakeSkipLBMap{lb4Events: lbEvents}

	added, err := m.rpm.AddRedirectPolicy(pc)

	require.Equal(t, true, added)
	require.Nil(t, err)

	wg := sync.WaitGroup{}
	// Asserts skipLBMap events
	wg.Add(1)
	go func() {
		ev := <-lbEvents

		require.Equal(t, ep.NetNsCookie, ev.cookie)
		require.Equal(t, fe1.AddrCluster.Addr().String(), ev.ip.String())
		require.Equal(t, fe1.L4Addr.Port, ev.port)

		wg.Done()
	}()
	// Asserts UpsertService events
	wg.Add(1)
	go func() {
		ev := <-sMgr.upsertEvents

		require.Equal(t, lb.SVCTypeLocalRedirect, ev.Type)
		require.Equal(t, configAddrType.frontendMappings[0].feAddr.String(), ev.Frontend.String())
		require.Equal(t, 1, len(ev.Backends))
		require.Equal(t, backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(pod1.Status.PodIP), L4Addr: beP1.l4Addr},
			podID:    pod1ID,
		}.Hash(), ev.Backends[0].Hash())

		wg.Done()
	}()

	// Add an endpoint for the policy selected pod.
	m.rpm.EndpointCreated(ep)

	// Wait for the skipLBMap and Upsert service events
	wg.Wait()

	// Sequence of events: Pod -> Endpoint -> RedirectPolicy
	sMgr = &fakeSvcManager{}
	sMgr.upsertEvents = make(chan *lb.SVC)
	m.svc = sMgr
	pod = pod1.DeepCopy()
	pod.Status.PodIPs = []slimcorev1.PodIP{pod1IP1}
	cookie := uint64(1235)
	ep = &endpoint.Endpoint{
		K8sPodName:   pod1.Name,
		K8sNamespace: pod1.Namespace,
		NetNsCookie:  cookie,
	}
	cookies := map[netip.Addr]uint64{}
	addr, _ := netip.ParseAddr(pod.Status.PodIP)
	cookies[addr] = cookie
	m.epM = &fakeEpManager{cookies: cookies}
	fps = &fakePodResource{
		fakePodStore{
			OnList: func() []*slimcorev1.Pod {
				return []*slimcorev1.Pod{pod}
			},
		},
	}
	m.rpm = NewRedirectPolicyManager(m.svc, nil, fps, m.epM)
	lbEvents = make(chan skipLBParams)
	m.rpm.skipLBMap = &fakeSkipLBMap{lb4Events: lbEvents}

	wg = sync.WaitGroup{}
	// Asserts skipLBMap events
	wg.Add(1)
	go func() {
		ev := <-lbEvents

		require.Equal(t, cookie, ev.cookie)
		require.Equal(t, fe1.AddrCluster.Addr().String(), ev.ip.String())
		require.Equal(t, fe1.L4Addr.Port, ev.port)

		wg.Done()
	}()
	// Asserts UpsertService events
	wg.Add(1)
	go func() {
		ev := <-sMgr.upsertEvents

		require.Equal(t, lb.SVCTypeLocalRedirect, ev.Type)
		require.Equal(t, configAddrType.frontendMappings[0].feAddr.String(), ev.Frontend.String())
		require.Equal(t, 1, len(ev.Backends))
		require.Equal(t, backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(pod.Status.PodIP), L4Addr: beP1.l4Addr},
			podID:    pod1ID,
		}.Hash(), ev.Backends[0].Hash())

		wg.Done()
	}()

	// Policy is added.
	added, err = m.rpm.AddRedirectPolicy(pc)

	require.Equal(t, true, added)
	require.Nil(t, err)

	wg.Wait()

	// Sequence of events: RedirectPolicy -> Pod -> Endpoint
	sMgr = &fakeSvcManager{}
	sMgr.upsertEvents = make(chan *lb.SVC)
	m.svc = sMgr
	pod = pod1.DeepCopy()
	pod.Status.PodIPs = []slimcorev1.PodIP{pod1IP1}
	cookie = uint64(1235)
	ep = &endpoint.Endpoint{
		K8sPodName:   pod1.Name,
		K8sNamespace: pod1.Namespace,
		NetNsCookie:  cookie,
	}
	m.epM = &fakeEpManager{}
	pods = make(map[resource.Key]*slimcorev1.Pod)
	pk1 = resource.Key{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
	}
	pods[pk1] = pod
	fps = &fakePodResource{
		fakePodStore{
			Pods: pods,
		},
	}
	m.rpm = NewRedirectPolicyManager(m.svc, nil, fps, m.epM)
	lbEvents = make(chan skipLBParams)
	m.rpm.skipLBMap = &fakeSkipLBMap{lb4Events: lbEvents}

	wg = sync.WaitGroup{}
	// Asserts skipLBMap events
	wg.Add(1)
	go func() {
		ev := <-lbEvents

		require.Equal(t, cookie, ev.cookie)
		require.Equal(t, fe1.AddrCluster.Addr().String(), ev.ip.String())
		require.Equal(t, fe1.L4Addr.Port, ev.port)

		wg.Done()
	}()
	// Asserts UpsertService events
	wg.Add(1)
	go func() {
		ev := <-sMgr.upsertEvents

		require.Equal(t, lb.SVCTypeLocalRedirect, ev.Type)
		require.Equal(t, configAddrType.frontendMappings[0].feAddr.String(), ev.Frontend.String())
		require.Equal(t, 1, len(ev.Backends))
		require.Equal(t, backend{
			L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(pod.Status.PodIP), L4Addr: beP1.l4Addr},
			podID:    pod1ID,
		}.Hash(), ev.Backends[0].Hash())

		wg.Done()
	}()

	// Policy is added.
	added, err = m.rpm.AddRedirectPolicy(pc)
	require.Equal(t, true, added)
	require.Nil(t, err)

	// Pod selected by the policy added.
	m.rpm.OnAddPod(pod)

	// Add an endpoint for the policy selected pod.
	m.rpm.EndpointCreated(ep)

	wg.Wait()
}

// Tests connections to deleted LRP backend pods getting terminated.
func TestManager_OnDeletePod(t *testing.T) {
	m := setupManagerSuite(t)

	option.Config.EnableSocketLB = true
	// Create an unbuffered channel so that the test blocks on unexpected events.
	events := make(chan lb.L3n4Addr)
	m.rpm.svcManager = &fakeSvcManager{destroyConnectionEvents: events}
	labels := map[string]string{"test": "foo-bar-term"}
	podUDP := &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-be",
			Namespace: "ns1",
			Labels:    labels,
		},
		Spec: slimcorev1.PodSpec{
			Containers: []slimcorev1.Container{
				{
					Ports: []slimcorev1.ContainerPort{
						{
							Name:          portName1,
							ContainerPort: pod2Port1,
							Protocol:      pod2Proto2,
						},
						{
							Name:          portName2,
							ContainerPort: pod2Port2,
							Protocol:      pod2Proto2,
						},
					},
				},
			},
		},
		Status: slimcorev1.PodStatus{
			PodIP:      pod2IP1.IP,
			PodIPs:     []slimcorev1.PodIP{pod2IP1},
			Conditions: []slimcorev1.PodCondition{podReady},
		},
	}
	beUDPP1 := bePortInfo{
		l4Addr: lb.L4Addr{
			Protocol: udpStr,
			Port:     uint16(podUDP.Spec.Containers[0].Ports[0].ContainerPort),
		},
		name: portName1,
	}
	beUDPP2 := bePortInfo{
		l4Addr: lb.L4Addr{
			Protocol: udpStr,
			Port:     uint16(podUDP.Spec.Containers[0].Ports[1].ContainerPort),
		},
		name: portName2,
	}
	beAddrs := sets.New[lb.L3n4Addr]()
	beAddrs.Insert(lb.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster(podUDP.Status.PodIP), L4Addr: beUDPP1.l4Addr})
	beAddrs.Insert(lb.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster(podUDP.Status.PodIP), L4Addr: beUDPP2.l4Addr})
	pc := LRPConfig{
		id: k8s.ServiceID{
			Name:      "test-foo",
			Namespace: "ns1",
		},
		lrpType:      lrpConfigTypeAddr,
		frontendType: addrFrontendNamedPorts,
		frontendMappings: []*feMapping{{
			feAddr:      fe2,
			podBackends: nil,
			fePort:      beUDPP1.name,
		}, {
			feAddr:      fe2,
			podBackends: nil,
			fePort:      beUDPP2.name,
		}},
		backendSelector: api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: labels,
			},
		},
		backendPorts: []bePortInfo{beUDPP1, beUDPP2},
		backendPortsByPortName: map[string]*bePortInfo{
			beUDPP1.name: &beUDPP1,
			beUDPP2.name: &beUDPP2,
		},
	}

	// Add an LRP.
	added, err := m.rpm.AddRedirectPolicy(pc)

	require.True(t, added)
	require.NoError(t, err)

	// Add LRP selected pod with UDP ports.
	m.rpm.OnAddPod(podUDP)
	// Assert connection termination events asynchronously.
	wg := sync.WaitGroup{}
	wg.Add(1)
	got := 0
	go func() {
		for {
			addr := <-events
			if beAddrs.Has(addr) {
				got++
			}
			if got == beAddrs.Len() {
				wg.Done()
				break
			}
		}
	}()
	// Delete the pod.
	m.rpm.OnDeletePod(podUDP)

	wg.Wait()
}
