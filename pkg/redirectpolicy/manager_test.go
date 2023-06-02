// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"testing"

	. "github.com/cilium/checkmate"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/checker"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ManagerSuite struct {
	rpm *Manager
	svc svcManager
}

var _ = Suite(&ManagerSuite{})

func (s *ManagerSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

type fakeSvcManager struct {
}

func (f *fakeSvcManager) DeleteService(lb.L3n4Addr) (bool, error) {
	return true, nil
}

func (f *fakeSvcManager) UpsertService(*lb.SVC) (bool, lb.ID, error) {
	return true, 1, nil
}

type fakePodStore struct {
	OnList func() []interface{}
}

func (ps *fakePodStore) List() []interface{} {
	if ps.OnList != nil {
		return ps.OnList()
	}
	pods := make([]interface{}, 2, 2)
	pods = append(pods, pod1, pod2)
	return pods
}

func (ps *fakePodStore) Add(obj interface{}) error {
	return nil
}

func (ps *fakePodStore) Update(obj interface{}) error {
	return nil
}

func (ps *fakePodStore) Delete(obj interface{}) error {
	return nil
}

func (ps *fakePodStore) ListKeys() []string {
	return nil
}

func (ps *fakePodStore) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, nil
}

func (ps *fakePodStore) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, nil
}

func (ps *fakePodStore) Replace(i []interface{}, s string) error {
	return nil
}

func (ps *fakePodStore) Resync() error {
	return nil
}

type fakePodStoreGetter struct {
	ps *fakePodStore
}

func (psg *fakePodStoreGetter) GetStore(name string) cache.Store {
	return psg.ps
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

func (m *ManagerSuite) SetUpTest(c *C) {
	m.svc = &fakeSvcManager{}
	m.rpm = NewRedirectPolicyManager(m.svc)
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
}

// Tests if duplicate addressMatcher configs are not added.
func (m *ManagerSuite) TestManager_AddRedirectPolicy_AddrMatcherDuplicateConfig(c *C) {
	configFe := configAddrType
	m.rpm.policyFrontendsByHash[fe1.Hash()] = configFe.id
	dupConfigFe := configFe
	dupConfigFe.id.Name = "test-foo2"

	added, err := m.rpm.AddRedirectPolicy(dupConfigFe)

	c.Assert(added, Equals, false)
	c.Assert(err, NotNil)
}

// Tests if duplicate svcMatcher configs are not added.
func (m *ManagerSuite) TestManager_AddRedirectPolicy_SvcMatcherDuplicateConfig(c *C) {
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

	c.Assert(added, Equals, false)
	c.Assert(err, NotNil)
}

// Tests add redirect policy, add pod, delete pod and delete redirect policy events
// for an addressMatcher config with a frontend having single port.
func (m *ManagerSuite) TestManager_AddrMatcherConfigSinglePort(c *C) {
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

	m.rpm.RegisterGetStores(&fakePodStoreGetter{ps: &fakePodStore{}})

	added, err := m.rpm.AddRedirectPolicy(configAddrType)

	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(m.rpm.policyConfigs), Equals, 1)
	c.Assert(m.rpm.policyConfigs[configAddrType.id].id.Name, Equals, configAddrType.id.Name)
	c.Assert(m.rpm.policyConfigs[configAddrType.id].id.Namespace, Equals, configAddrType.id.Namespace)
	c.Assert(len(m.rpm.policyFrontendsByHash), Equals, 1)
	c.Assert(m.rpm.policyFrontendsByHash[configAddrType.frontendMappings[0].feAddr.Hash()],
		Equals, configAddrType.id)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals, 2)
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals, expectedbes[i])
	}
	c.Assert(len(m.rpm.policyPods), Equals, 1)
	c.Assert(len(m.rpm.policyPods[pod1ID]), Equals, 1)
	c.Assert(m.rpm.policyPods[pod1ID][0], Equals, configAddrType.id)

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

	c.Assert(len(m.rpm.policyPods), Equals, 2)
	c.Assert(len(m.rpm.policyPods[pod3ID]), Equals, 1)
	c.Assert(m.rpm.policyPods[pod1ID][0], Equals, configAddrType.id)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals, 4)
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals, expectedbes2[i])
	}

	// When pod becomes un-ready
	pod3.Status.Conditions = []slimcorev1.PodCondition{podNotReady}
	m.rpm.OnUpdatePod(pod3, false, false)

	c.Assert(len(m.rpm.policyPods), Equals, 2)
	c.Assert(len(m.rpm.policyPods[pod3ID]), Equals, 1)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals, 2)
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals, expectedbes[i])
	}

	// When pod becomes ready
	pod3.Status.Conditions = []slimcorev1.PodCondition{podReady}
	m.rpm.OnUpdatePod(pod3, false, true)

	c.Assert(len(m.rpm.policyPods), Equals, 2)
	c.Assert(len(m.rpm.policyPods[pod3ID]), Equals, 1)
	c.Assert(m.rpm.policyPods[pod1ID][0], Equals, configAddrType.id)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals, 4)
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals, expectedbes2[i])
	}

	// Delete the pod. This should delete the pod's backends.
	m.rpm.OnDeletePod(pod3)

	c.Assert(len(m.rpm.policyPods), Equals, 1)
	_, found := m.rpm.policyPods[pod3ID]
	c.Assert(found, Equals, false)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals, 2)
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals, expectedbes[i])
	}

	// Delete the LRP.
	err = m.rpm.DeleteRedirectPolicy(configAddrType)

	c.Assert(err, IsNil)
	c.Assert(len(m.rpm.policyFrontendsByHash), Equals, 0)
	c.Assert(len(m.rpm.policyPods), Equals, 0)
	c.Assert(len(m.rpm.policyConfigs), Equals, 0)
}

// Tests add redirect policy, add pod, delete pod and delete redirect policy events
// for an addressMatcher config with a frontend having multiple named ports.
func (m *ManagerSuite) TestManager_AddrMatcherConfigMultiplePorts(c *C) {
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

	m.rpm.RegisterGetStores(&fakePodStoreGetter{ps: &fakePodStore{}})

	added, err := m.rpm.AddRedirectPolicy(configAddrType)

	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(m.rpm.policyConfigs), Equals, 1)
	c.Assert(m.rpm.policyConfigs[configAddrType.id].id.Name, Equals, configAddrType.id.Name)
	c.Assert(m.rpm.policyConfigs[configAddrType.id].id.Namespace, Equals, configAddrType.id.Namespace)
	c.Assert(len(m.rpm.policyFrontendsByHash), Equals, 2)
	for _, id := range m.rpm.policyFrontendsByHash {
		c.Assert(id, Equals, configAddrType.id)
	}
	// Frontend ports should be mapped to the corresponding backend ports.
	for _, feM := range configAddrType.frontendMappings {
		switch feM.fePort {
		case "test1":
			c.Assert(len(feM.podBackends), Equals, 2)
			for i := range podIPs {
				expectedbes[i] = backend{
					L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP1.l4Addr},
					podID:    pod1ID,
				}
			}
			for i := range feM.podBackends {
				c.Assert(feM.podBackends[i], checker.Equals, expectedbes[i])
			}
		case "test2":
			c.Assert(len(feM.podBackends), Equals, 2)
			for i := range podIPs {
				expectedbes[i] = backend{
					L3n4Addr: lb.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(podIPs[i]), L4Addr: beP2.l4Addr},
					podID:    pod1ID,
				}
			}
			for i := range feM.podBackends {
				c.Assert(feM.podBackends[i], checker.Equals, expectedbes[i])
			}
		default:
			log.Errorf("Unknown port %s", feM.fePort)
		}
	}
	c.Assert(len(m.rpm.policyPods), Equals, 1)
	c.Assert(len(m.rpm.policyPods[pod1ID]), Equals, 1)
	c.Assert(m.rpm.policyPods[pod1ID][0], Equals, configAddrType.id)

	// Delete the LRP.
	err = m.rpm.DeleteRedirectPolicy(configAddrType)

	c.Assert(err, IsNil)
	c.Assert(len(m.rpm.policyFrontendsByHash), Equals, 0)
	c.Assert(len(m.rpm.policyPods), Equals, 0)
	c.Assert(len(m.rpm.policyConfigs), Equals, 0)
}

// Tests if frontend ipv4 and ipv6 addresses are mapped to the ipv4 and ipv6
// backends, respectively.
func (m *ManagerSuite) TestManager_AddrMatcherConfigDualStack(c *C) {
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
	psg := &fakePodStoreGetter{
		&fakePodStore{
			OnList: func() []interface{} {
				return []interface{}{pod3}
			},
		},
	}
	m.rpm.RegisterGetStores(psg)

	added, err := m.rpm.AddRedirectPolicy(configAddrType)

	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals,
		len(expectedbes4))
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals,
			expectedbes4[i])
	}

	// Only ipv6 backend(s) for ipv6 frontend
	feM := []*feMapping{{
		feAddr:      fe3v6,
		podBackends: nil,
	}}
	configAddrType.id.Name = "test-bar"
	configAddrType.frontendMappings = feM

	added, err = m.rpm.AddRedirectPolicy(configAddrType)

	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(configAddrType.frontendMappings[0].podBackends), Equals,
		len(expectedbes6))
	for i := range configAddrType.frontendMappings[0].podBackends {
		c.Assert(configAddrType.frontendMappings[0].podBackends[i], checker.Equals,
			expectedbes6[i])
	}
}

// Tests add and update pod operations with namespace mismatched pods.
func (m *ManagerSuite) TestManager_OnAddandUpdatePod(c *C) {
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
	c.Assert(len(m.rpm.policyPods), Equals, 0)
	_, found := m.rpm.policyPods[podID]
	c.Assert(found, Equals, false)

	m.rpm.OnUpdatePod(pod, true, true)

	// Namespace mismatched pod not selected.
	c.Assert(len(m.rpm.policyPods), Equals, 0)
	_, found = m.rpm.policyPods[podID]
	c.Assert(found, Equals, false)
}
