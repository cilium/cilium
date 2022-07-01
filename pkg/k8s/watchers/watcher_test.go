// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package watchers

import (
	"bytes"
	"context"
	"net"
	"sort"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/service"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sWatcherSuite struct{}

var _ = Suite(&K8sWatcherSuite{})

type fakeWatcherConfiguration struct{}

func (f *fakeWatcherConfiguration) K8sServiceProxyNameValue() string {
	return ""
}

func (f *fakeWatcherConfiguration) K8sIngressControllerEnabled() bool {
	return false
}

type fakeEndpointManager struct {
	OnGetEndpoints                func() []*endpoint.Endpoint
	OnLookupPodName               func(string) *endpoint.Endpoint
	OnWaitForEndpointsAtPolicyRev func(ctx context.Context, rev uint64) error
}

func (f *fakeEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	if f.OnGetEndpoints != nil {
		return f.OnGetEndpoints()
	}
	panic("OnGetEndpoints was called and is not set!")
}

func (f *fakeEndpointManager) LookupPodName(podName string) *endpoint.Endpoint {
	if f.OnLookupPodName != nil {
		return f.OnLookupPodName(podName)
	}
	panic("OnLookupPodName(string) was called and is not set!")
}

func (f *fakeEndpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	if f.OnWaitForEndpointsAtPolicyRev != nil {
		return f.OnWaitForEndpointsAtPolicyRev(ctx, rev)
	}
	panic("OnWaitForEndpointsAtPolicyRev(context.Context, uint64) was called and is not set!")
}

type fakeNodeDiscoverManager struct {
	OnNodeDeleted                  func(n nodeTypes.Node)
	OnNodeUpdated                  func(n nodeTypes.Node)
	OnClusterSizeDependantInterval func(baseInterval time.Duration) time.Duration
}

func (f *fakeNodeDiscoverManager) NodeDeleted(n nodeTypes.Node) {
	if f.OnNodeDeleted != nil {
		f.OnNodeDeleted(n)
		return
	}
	panic("OnNodeDeleted(node) was called and is not set!")
}

func (f *fakeNodeDiscoverManager) NodeUpdated(n nodeTypes.Node) {
	if f.OnNodeUpdated != nil {
		f.OnNodeUpdated(n)
		return
	}
	panic("OnNodeUpdated(node) was called and is not set!")
}

func (f *fakeNodeDiscoverManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	if f.OnClusterSizeDependantInterval != nil {
		return f.OnClusterSizeDependantInterval(baseInterval)
	}
	panic("OnClusterSizeDependantInterval(time.Duration) was called and is not set!")
}

type fakePolicyManager struct {
	OnTriggerPolicyUpdates func(force bool, reason string)
	OnPolicyAdd            func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	OnPolicyDelete         func(labels labels.LabelArray) (newRev uint64, err error)
}

func (f *fakePolicyManager) TriggerPolicyUpdates(force bool, reason string) {
	if f.OnTriggerPolicyUpdates != nil {
		f.OnTriggerPolicyUpdates(force, reason)
		return
	}
	panic("OnTriggerPolicyUpdates(force bool, reason string) was called and is not set!")
}

func (f *fakePolicyManager) PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
	if f.OnPolicyAdd != nil {
		return f.OnPolicyAdd(rules, opts)
	}
	panic("OnPolicyAdd(api.Rules, *policy.AddOptions) (uint64, error) was called and is not set!")
}

func (f *fakePolicyManager) PolicyDelete(labels labels.LabelArray) (newRev uint64, err error) {
	if f.OnPolicyDelete != nil {
		return f.OnPolicyDelete(labels)
	}
	panic("OnPolicyDelete(labels.LabelArray) (uint64, error) was called and is not set!")
}

type fakePolicyRepository struct {
	OnGetSelectorCache func() *policy.SelectorCache
	OnTranslateRules   func(translator policy.Translator) (*policy.TranslationResult, error)
}

func (f *fakePolicyRepository) GetSelectorCache() *policy.SelectorCache {
	if f.OnGetSelectorCache != nil {
		return f.OnGetSelectorCache()
	}
	panic("OnGetSelectorCache() (*policy.SelectorCache) was called and is not set!")
}

func (f *fakePolicyRepository) TranslateRules(translator policy.Translator) (*policy.TranslationResult, error) {
	if f.OnTranslateRules != nil {
		return f.OnTranslateRules(translator)
	}
	panic("OnTranslateRules(policy.Translator) (*policy.TranslationResult, error) was called and is not set!")
}

type fakeSvcManager struct {
	OnDeleteService func(frontend loadbalancer.L3n4Addr) (bool, error)
	OnUpsertService func(*loadbalancer.SVC) (bool, loadbalancer.ID, error)
}

func (f *fakeSvcManager) DeleteService(frontend loadbalancer.L3n4Addr) (bool, error) {
	if f.OnDeleteService != nil {
		return f.OnDeleteService(frontend)
	}
	panic("OnDeleteService(loadbalancer.L3n4Addr) (bool, error) was called and is not set!")
}

func (f *fakeSvcManager) UpsertService(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
	if f.OnUpsertService != nil {
		return f.OnUpsertService(p)
	}
	panic("OnUpsertService() was called and is not set!")
}

func (f *fakeSvcManager) RegisterL7LBService(serviceName, resourceName service.Name, ports []string, proxyPort uint16) error {
	return nil
}

func (f *fakeSvcManager) RegisterL7LBServiceBackendSync(serviceName, resourceName service.Name, ports []string) error {
	return nil
}

func (f *fakeSvcManager) RemoveL7LBService(serviceName, resourceName service.Name) error {
	return nil
}

func (s *K8sWatcherSuite) TestUpdateToServiceEndpointsGH9525(c *C) {

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	ep2ndApply := ep1stApply.DeepCopy()
	ep2ndApply.Subsets[0].Addresses = append(
		ep2ndApply.Subsets[0].Addresses,
		slim_corev1.EndpointAddress{IP: "10.0.0.3"},
	)

	policyManagerCalls := 0
	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
			policyManagerCalls++
		},
	}
	policyRepositoryCalls := 0
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			rt, ok := tr.(k8s.RuleTranslator)
			c.Assert(ok, Equals, true)
			switch policyRepositoryCalls {
			case 0:
				_, parsedEPs := k8s.ParseEndpoints(ep1stApply)
				c.Assert(rt.Endpoint.Backends, checker.DeepEquals, parsedEPs.Backends)
			case 1:
				_, parsedEPs := k8s.ParseEndpoints(ep2ndApply)
				c.Assert(rt.Endpoint.Backends, checker.DeepEquals, parsedEPs.Backends)
			default:
				c.Assert(policyRepositoryCalls, Not(Equals), 0, Commentf("policy repository was called more times than expected!"))
			}
			policyRepositoryCalls++

			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		nil,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	w.K8sSvcCache.UpdateService(k8sSvc, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	// Running a 2nd update should also trigger a new policy update
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)

	swg.Stop()
	swg.Wait()

	c.Assert(policyRepositoryCalls, Equals, 2)
	c.Assert(policyManagerCalls, Equals, 2)
}

func (s *K8sWatcherSuite) Test_addK8sSVCs_ClusterIP(c *C) {
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     80,
				},
				// FIXME: We don't distinguish about the protocol being used
				//        so we can't tell if a UDP/80 maps to port 8080/udp
				//        or if TCP/80 maps to port 8081/TCP
				// {
				// 	Name:       "port-tcp-80",
				// 	Protocol:  slim_corev1.ProtocolTCP,
				// 	Port:       80,
				// 	TargetPort: intstr.FromString("port-80-t"),
				// },
				{
					Name:     "port-tcp-81",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     81,
				},
			},
			Selector:              nil,
			ClusterIP:             "172.0.20.1",
			Type:                  slim_corev1.ServiceTypeClusterIP,
			ExternalIPs:           nil,
			SessionAffinity:       "",
			ExternalTrafficPolicy: "",
			HealthCheckNodePort:   0,
			SessionAffinityConfig: nil,
		},
	}

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
					// FIXME: We don't distinguish about the protocol being used
					//        so we can't tell if a UDP/80 maps to port 8080/udp
					//        or if TCP/80 maps to port 8081/TCP
					// {
					// 	Name:     "port-tcp-80",
					// 	Protocol:slim_corev1.ProtocolTCP,
					// 	Port:     8081,
					// },
					{
						Name:     "port-tcp-81",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     81,
					},
				},
			},
		},
	}

	lb1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	// lb2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	lb3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)
	upsert1stWanted := map[string]loadbalancer.SVC{
		lb1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// lb2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *lb2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		lb3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     81,
						},
					},
				},
			},
		},
	}

	ep2ndApply := ep1stApply.DeepCopy()
	ep2ndApply.Subsets[0].Addresses = append(
		ep2ndApply.Subsets[0].Addresses,
		slim_corev1.EndpointAddress{IP: "10.0.0.3"},
	)

	upsert2ndWanted := map[string]loadbalancer.SVC{
		lb1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// lb2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *lb2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.3"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		lb3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     81,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     81,
						},
					},
				},
			},
		},
	}

	del1stWanted := map[string]struct{}{
		lb1.Hash(): {},
		// lb2.Hash(): {},
		lb3.Hash(): {},
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	del1st := map[string]struct{}{}

	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
		},
	}
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return bytes.Compare(p.Backends[i].IP, p.Backends[j].IP) < 0
			})
			switch {
			// 1st update endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted):
				upsert1st[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			// 2nd update endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted)+len(upsert2ndWanted):
				upsert2nd[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			}
			svcUpsertManagerCalls++
			return false, 0, nil
		},
		OnDeleteService: func(fe loadbalancer.L3n4Addr) (b bool, e error) {
			del1st[fe.Hash()] = struct{}{}
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		svcManager,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	w.K8sSvcCache.UpdateService(k8sSvc, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	// Running a 2nd update should also trigger a new upsert service
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)
	// Running a 3rd update should also not trigger anything because the
	// endpoints are the same
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)

	w.K8sSvcCache.DeleteService(k8sSvc, swg)

	swg.Stop()
	swg.Wait()
	c.Assert(svcUpsertManagerCalls, Equals, len(upsert1stWanted)+len(upsert2ndWanted))
	c.Assert(svcDeleteManagerCalls, Equals, len(del1stWanted))

	c.Assert(upsert1st, checker.DeepEquals, upsert1stWanted)
	c.Assert(upsert2nd, checker.DeepEquals, upsert2ndWanted)
	c.Assert(del1st, checker.DeepEquals, del1stWanted)
}

func (s *K8sWatcherSuite) TestChangeSVCPort(c *C) {
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     80,
				},
			},
			ClusterIP: "172.0.20.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
				},
			},
		},
	}

	lb1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	lb2 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)
	upsertsWanted := []loadbalancer.SVC{
		{
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		{
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb2,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
	}

	k8sSvcChanged := k8sSvc.DeepCopy()
	k8sSvcChanged.Spec.Ports[0].Port = 81

	upserts := []loadbalancer.SVC{}

	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
		},
	}
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	svcUpsertManagerCalls := 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			upserts = append(upserts, loadbalancer.SVC{
				Frontend: p.Frontend,
				Backends: p.Backends,
				Type:     p.Type,
			})
			svcUpsertManagerCalls++
			return false, 0, nil
		},
		OnDeleteService: func(fe loadbalancer.L3n4Addr) (b bool, e error) {
			return false, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		svcManager,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	w.K8sSvcCache.UpdateService(k8sSvc, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	w.K8sSvcCache.UpdateService(k8sSvcChanged, swg)

	swg.Stop()
	swg.Wait()
	c.Assert(svcUpsertManagerCalls, Equals, 2) // Add and Update events
	c.Assert(upserts, checker.DeepEquals, upsertsWanted)
}

func (s *K8sWatcherSuite) Test_addK8sSVCs_NodePort(c *C) {
	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = enableNodePortBak
	}()

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     80,
					NodePort: 18080,
				},
				// FIXME: We don't distinguish about the protocol being used
				//        so we can't tell if a UDP/80 maps to port 8080/udp
				//        or if TCP/80 maps to port 8081/TCP
				// {
				// 	Name:       "port-tcp-80",
				// 	Protocol:  slim_corev1.ProtocolTCP,
				// 	Port:       80,
				// 	TargetPort: intstr.FromString("port-80-t"),
				//  NodePort:   18080,
				// },
				{
					Name:     "port-tcp-81",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     81,
					NodePort: 18081,
				},
			},
			Selector:              nil,
			ClusterIP:             "172.0.20.1",
			Type:                  slim_corev1.ServiceTypeNodePort,
			ExternalIPs:           nil,
			SessionAffinity:       "",
			ExternalTrafficPolicy: "",
			HealthCheckNodePort:   0,
			SessionAffinityConfig: nil,
		},
	}

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
					// FIXME: We don't distinguish about the protocol being used
					//        so we can't tell if a UDP/80 maps to port 8080/udp
					//        or if TCP/80 maps to port 8081/TCP
					// {
					// 	Name:     "port-tcp-80",
					// 	Protocol:slim_corev1.ProtocolTCP,
					// 	Port:     8081,
					// },
					{
						Name:     "port-tcp-81",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
					},
				},
			},
		},
	}

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	// clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// clusterIP2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *clusterIP2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4NodePortAddress, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4InternalAddress, 18080, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// nodePortIPs2 := []*loadbalancer.L3n4AddrID{
	// 	loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
	// 	loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.Pv4NodePortAddress, 18080, loadbalancer.ScopeExternal, 0),
	// 	loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4InternalAddress, 18080, loadbalancer.ScopeExternal, 0),
	// }
	// for _, nodePort := range nodePortIPs2 {
	// 	upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeNodePort,
	// 		Frontend: *nodePort,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	nodePortIPs3 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4NodePortAddress, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4InternalAddress, 18081, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs3 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	ep2ndApply := ep1stApply.DeepCopy()
	ep2ndApply.Subsets[0].Addresses = append(
		ep2ndApply.Subsets[0].Addresses,
		slim_corev1.EndpointAddress{IP: "10.0.0.3"},
	)

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// clusterIP2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *clusterIP2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.3"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}

	for _, nodePort := range nodePortIPs1 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// for _, nodePort := range nodePortIPs2 {
	// 	upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeNodePort,
	// 		Frontend: *nodePort,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.3"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	for _, nodePort := range nodePortIPs3 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	del1stWanted := map[string]struct{}{
		clusterIP1.Hash(): {},
		// clusterIP2.Hash(): {},
		clusterIP3.Hash(): {},
	}
	for _, nodePort := range append(nodePortIPs1, nodePortIPs3...) {
		del1stWanted[nodePort.Hash()] = struct{}{}
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	del1st := map[string]struct{}{}

	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
		},
	}
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return bytes.Compare(p.Backends[i].IP, p.Backends[j].IP) < 0
			})
			switch {
			// 1st update endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted):
				upsert1st[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			// 2nd update endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted)+len(upsert2ndWanted):
				upsert2nd[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			}
			svcUpsertManagerCalls++
			return false, 0, nil
		},
		OnDeleteService: func(fe loadbalancer.L3n4Addr) (b bool, e error) {
			del1st[fe.Hash()] = struct{}{}
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		svcManager,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	w.K8sSvcCache.UpdateService(k8sSvc, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	// Running a 2nd update should also trigger a new upsert service
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)
	// Running a 3rd update should not trigger anything because the
	// endpoints are the same
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)

	w.K8sSvcCache.DeleteService(k8sSvc, swg)

	swg.Stop()
	swg.Wait()
	c.Assert(svcUpsertManagerCalls, Equals, len(upsert1stWanted)+len(upsert2ndWanted))
	c.Assert(svcDeleteManagerCalls, Equals, len(del1stWanted))

	c.Assert(upsert1st, checker.DeepEquals, upsert1stWanted)
	c.Assert(upsert2nd, checker.DeepEquals, upsert2ndWanted)
	c.Assert(del1st, checker.DeepEquals, del1stWanted)
}

func (s *K8sWatcherSuite) Test_addK8sSVCs_GH9576_1(c *C) {
	// Adding service without any endpoints and later on modifying the service,
	// cilium should:
	// 1) delete the non existing services from the datapath.

	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = enableNodePortBak
	}()

	k8sSvc1stApply := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     80,
					NodePort: 18080,
				},
				{
					Name:     "port-tcp-81",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     81,
					NodePort: 18081,
				},
			},
			ClusterIP: "172.0.20.1",
			Type:      slim_corev1.ServiceTypeNodePort,
		},
	}

	k8sSvc2ndApply := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     8083,
				},
				{
					Name:     "port-tcp-81",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     81,
				},
			},
			ClusterIP: "172.0.20.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
					{
						Name:     "port-tcp-81",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
					},
				},
			},
		},
	}

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4NodePortAddress, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4InternalAddress, 18080, loadbalancer.ScopeExternal, 0),
	}
	nodePortIPs2 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4NodePortAddress, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4InternalAddress, 18081, loadbalancer.ScopeExternal, 0),
	}

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	clusterIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 8083, loadbalancer.ScopeExternal, 0)

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
	}

	del1stWanted := map[string]loadbalancer.L3n4Addr{
		clusterIP1.Hash(): clusterIP1.L3n4Addr,
	}
	for _, nodePort := range append(nodePortIPs1, nodePortIPs2...) {
		del1stWanted[nodePort.Hash()] = nodePort.L3n4Addr
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	del1st := map[string]loadbalancer.L3n4Addr{}

	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
		},
	}
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0
	wantSvcUpsertManagerCalls := len(upsert1stWanted) + len(upsert2ndWanted)
	wantSvcDeleteManagerCalls := len(del1stWanted)

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return bytes.Compare(p.Backends[i].IP, p.Backends[j].IP) < 0
			})
			switch {
			// 1st update service-endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted):
				upsert1st[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			// 2nd update services
			case svcUpsertManagerCalls < len(upsert1stWanted)+len(upsert2ndWanted):
				upsert2nd[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			}
			svcUpsertManagerCalls++
			return false, 0, nil
		},
		OnDeleteService: func(fe loadbalancer.L3n4Addr) (b bool, e error) {
			del1st[fe.Hash()] = fe
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		svcManager,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	w.K8sSvcCache.UpdateService(k8sSvc1stApply, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)

	w.K8sSvcCache.UpdateService(k8sSvc2ndApply, swg)

	swg.Stop()
	swg.Wait()
	c.Assert(svcUpsertManagerCalls, Equals, wantSvcUpsertManagerCalls)
	c.Assert(svcDeleteManagerCalls, Equals, wantSvcDeleteManagerCalls)

	c.Assert(upsert1st, checker.DeepEquals, upsert1stWanted)
	c.Assert(upsert2nd, checker.DeepEquals, upsert2ndWanted)
	c.Assert(del1st, checker.DeepEquals, del1stWanted)
}

func (s *K8sWatcherSuite) Test_addK8sSVCs_GH9576_2(c *C) {
	// Adding service without any endpoints and later on modifying the service,
	// cilium should:
	// 1) delete the non existing endpoints from the datapath, i.e., updating
	//    services without any backend.

	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = enableNodePortBak
	}()

	k8sSvc1stApply := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     80,
					NodePort: 18080,
				},
				{
					Name:     "port-tcp-81",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     81,
					NodePort: 18081,
				},
			},
			ClusterIP: "172.0.20.1",
			Type:      slim_corev1.ServiceTypeNodePort,
		},
	}

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
					{
						Name:     "port-tcp-81",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
					},
				},
			},
		},
	}

	ep2ndApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.3"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
				},
			},
		},
	}

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4NodePortAddress, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4InternalAddress, 18080, loadbalancer.ScopeExternal, 0),
	}
	nodePortIPs2 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4NodePortAddress, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4InternalAddress, 18081, loadbalancer.ScopeExternal, 0),
	}

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
		},
	}
	for _, nodePort := range nodePortIPs1 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
		}
	}

	del1stWanted := map[string]loadbalancer.L3n4Addr{}
	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	del1st := map[string]loadbalancer.L3n4Addr{}

	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
		},
	}
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0
	wantSvcUpsertManagerCalls := len(upsert1stWanted) + len(upsert2ndWanted)
	wantSvcDeleteManagerCalls := len(del1stWanted)

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return bytes.Compare(p.Backends[i].IP, p.Backends[j].IP) < 0
			})
			switch {
			// 1st update service-endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted):
				upsert1st[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			// 2nd update services
			case svcUpsertManagerCalls < len(upsert1stWanted)+len(upsert2ndWanted):
				upsert2nd[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			}
			svcUpsertManagerCalls++
			return false, 0, nil
		},
		OnDeleteService: func(fe loadbalancer.L3n4Addr) (b bool, e error) {
			del1st[fe.Hash()] = fe
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		svcManager,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	w.K8sSvcCache.UpdateService(k8sSvc1stApply, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)

	swg.Stop()
	swg.Wait()

	c.Assert(svcUpsertManagerCalls, Equals, wantSvcUpsertManagerCalls)
	c.Assert(svcDeleteManagerCalls, Equals, wantSvcDeleteManagerCalls)

	c.Assert(upsert1st, checker.DeepEquals, upsert1stWanted)
	c.Assert(upsert2nd, checker.DeepEquals, upsert2ndWanted)
	c.Assert(del1st, checker.DeepEquals, del1stWanted)
}

func (s *K8sWatcherSuite) Test_addK8sSVCs_ExternalIPs(c *C) {
	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	defer func() {
		option.Config.EnableNodePort = enableNodePortBak
	}()

	svc1stApply := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "port-udp-80",
					Protocol: slim_corev1.ProtocolUDP,
					Port:     80,
					NodePort: 18080,
				},
				// FIXME: We don't distinguish about the protocol being used
				//        so we can't tell if a UDP/80 maps to port 8080/udp
				//        or if TCP/80 maps to port 8081/TCP
				// {
				// 	Name:       "port-tcp-80",
				// 	Protocol:  slim_corev1.ProtocolTCP,
				// 	Port:       80,
				// 	TargetPort: intstr.FromString("port-80-t"),
				//  NodePort:   18080,
				// },
				{
					Name:     "port-tcp-81",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     81,
					NodePort: 18081,
				},
			},
			Selector:              nil,
			ClusterIP:             "172.0.20.1",
			Type:                  slim_corev1.ServiceTypeNodePort,
			ExternalIPs:           []string{"127.8.8.8", "127.9.9.9"},
			SessionAffinity:       "",
			ExternalTrafficPolicy: "",
			HealthCheckNodePort:   0,
			SessionAffinityConfig: nil,
		},
	}

	svc2ndApply := svc1stApply.DeepCopy()
	svc2ndApply.Spec.ExternalIPs = []string{"127.8.8.8"}

	ep1stApply := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "10.0.0.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "port-udp-80",
						Port:     8080,
						Protocol: slim_corev1.ProtocolUDP,
					},
					// FIXME: We don't distinguish about the protocol being used
					//        so we can't tell if a UDP/80 maps to port 8080/udp
					//        or if TCP/80 maps to port 8081/TCP
					// {
					// 	Name:     "port-tcp-80",
					// 	Protocol:slim_corev1.ProtocolTCP,
					// 	Port:     8081,
					// },
					{
						Name:     "port-tcp-81",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
					},
				},
			},
		},
	}

	ep2ndApply := ep1stApply.DeepCopy()
	ep2ndApply.Subsets[0].Addresses = append(
		ep2ndApply.Subsets[0].Addresses,
		slim_corev1.EndpointAddress{IP: "10.0.0.3"},
	)

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	// clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// clusterIP2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *clusterIP2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}

	externalIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("127.8.8.8"), 80, loadbalancer.ScopeExternal, 0)
	// externalIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("127.8.8.8"), 80, loadbalancer.ScopeExternal, 0)
	externalIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("127.8.8.8"), 81, loadbalancer.ScopeExternal, 0)
	externalIP4 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("127.9.9.9"), 80, loadbalancer.ScopeExternal, 0)
	// externalIP5 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("127.9.9.9"), 80, loadbalancer.ScopeExternal, 0)
	externalIP6 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("127.9.9.9"), 81, loadbalancer.ScopeExternal, 0)
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP1, externalIP4} {
		upsert1stWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP2, externalIP5} {
	// 	upsert1stWanted[externalIP.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeExternalIPs,
	// 		Frontend: *externalIP,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.UDP,
	// 						Port:     8080,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP3, externalIP6} {
		upsert1stWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, net.ParseIP("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4NodePortAddress, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, fakeDatapath.IPv4InternalAddress, 18080, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// nodePortIPs2 := []*loadbalancer.L3n4AddrID{
	// 	loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
	// 	loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4NodePortAddress, 18080, loadbalancer.ScopeExternal, 0),
	// 	loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4InternalAddress, 18080, loadbalancer.ScopeExternal, 0),
	// }
	// for _, nodePort := range nodePortIPs2 {
	// 	upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeNodePort,
	// 		Frontend: *nodePort,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	nodePortIPs3 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, net.ParseIP("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4NodePortAddress, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, fakeDatapath.IPv4InternalAddress, 18081, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs3 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// clusterIP2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *clusterIP2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.3"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}

	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP1, externalIP4} {
		upsert2ndWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP2, externalIP5} {
	// 	upsert2ndWanted[externalIP.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeExternalIPs,
	// 		Frontend: *externalIP,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.UDP,
	// 						Port:     8080,
	// 					},
	// 				},
	// 			},
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.3"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP3, externalIP6} {
		upsert2ndWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	for _, nodePort := range nodePortIPs1 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// for _, nodePort := range nodePortIPs2 {
	// 	upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeNodePort,
	// 		Frontend: *nodePort,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.3"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	for _, nodePort := range nodePortIPs3 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	upsert3rdWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		},
		// FIXME: We don't distinguish about the protocol being used
		//        so we can't tell if a UDP/80 maps to port 8080/udp
		//        or if TCP/80 maps to port 8081/TCP
		// clusterIP2.Hash(): {
		// 	Type:     loadbalancer.SVCTypeClusterIP,
		// 	Frontend: *clusterIP2,
		// 	Backends: []loadbalancer.Backend{
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.2"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 		{
		// 			L3n4Addr: loadbalancer.L3n4Addr{
		// 				IP: net.ParseIP("10.0.0.3"),
		// 				L4Addr: loadbalancer.L4Addr{
		// 					Protocol: loadbalancer.TCP,
		// 					Port:     8081,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		},
	}

	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP1} {
		upsert3rdWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP2} {
	// 	upsert3rdWanted[externalIP.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeExternalIPs,
	// 		Frontend: *externalIP,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.3"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP3} {
		upsert3rdWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	for _, nodePort := range nodePortIPs1 {
		upsert3rdWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
				},
			},
		}
	}
	// for _, nodePort := range nodePortIPs2 {
	// 	upsert3rdWanted[nodePort.Hash()] = loadbalancer.SVC{
	// 		Type:     loadbalancer.SVCTypeNodePort,
	// 		Frontend: *nodePort,
	// 		Backends: []loadbalancer.Backend{
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.2"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 			{
	// 				L3n4Addr: loadbalancer.L3n4Addr{
	// 					IP: net.ParseIP("10.0.0.3"),
	// 					L4Addr: loadbalancer.L4Addr{
	// 						Protocol: loadbalancer.TCP,
	// 						Port:     8081,
	// 					},
	// 				},
	// 			},
	// 		},
	// 	}
	// }
	for _, nodePort := range nodePortIPs3 {
		upsert3rdWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
				},
			},
		}
	}

	del1stWanted := map[string]struct{}{
		externalIP4.Hash(): {},
		// externalIP5.Hash():{},
		externalIP6.Hash(): {},
	}
	del2ndWanted := map[string]struct{}{
		clusterIP1.Hash(): {},
		// clusterIP2.Hash(): {},
		clusterIP3.Hash():  {},
		externalIP1.Hash(): {},
		// externalIP2.Hash():{},
		externalIP3.Hash(): {},
	}
	for _, nodePort := range append(nodePortIPs1, nodePortIPs3...) {
		del2ndWanted[nodePort.Hash()] = struct{}{}
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	upsert3rd := map[string]loadbalancer.SVC{}
	del1st := map[string]struct{}{}
	del2nd := map[string]struct{}{}

	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
		},
	}
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return bytes.Compare(p.Backends[i].IP, p.Backends[j].IP) < 0
			})
			switch {
			// 1st update endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted):
				upsert1st[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			// 2nd update endpoints
			case svcUpsertManagerCalls < len(upsert1stWanted)+len(upsert2ndWanted):
				upsert2nd[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			// 3rd update services
			case svcUpsertManagerCalls < len(upsert1stWanted)+len(upsert2ndWanted)+len(upsert3rdWanted):
				upsert3rd[p.Frontend.Hash()] = loadbalancer.SVC{
					Frontend: p.Frontend,
					Backends: p.Backends,
					Type:     p.Type,
				}
			}
			svcUpsertManagerCalls++
			return false, 0, nil
		},
		OnDeleteService: func(fe loadbalancer.L3n4Addr) (b bool, e error) {
			switch {
			// 1st update endpoints
			case svcDeleteManagerCalls < len(del1stWanted):
				del1st[fe.Hash()] = struct{}{}
			// 2nd update endpoints
			case svcDeleteManagerCalls < len(del1stWanted)+len(del2ndWanted):
				del2nd[fe.Hash()] = struct{}{}
			}
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		svcManager,
		fakeDatapath.NewDatapath(),
		nil,
		nil,
		nil,
		nil,
		&fakeWatcherConfiguration{},
		ipcache.NewIPCache(nil),
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	w.K8sSvcCache.UpdateService(svc1stApply, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	// Running a 2nd update should also trigger a new upsert service
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)
	// Running a 3rd update should not trigger anything because the
	// endpoints are the same
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)

	w.K8sSvcCache.UpdateService(svc2ndApply, swg)

	w.K8sSvcCache.DeleteService(svc1stApply, swg)

	swg.Stop()
	swg.Wait()
	c.Assert(svcUpsertManagerCalls, Equals, len(upsert1stWanted)+len(upsert2ndWanted)+len(upsert3rdWanted))
	c.Assert(svcDeleteManagerCalls, Equals, len(del1stWanted)+len(del2ndWanted))

	c.Assert(upsert1st, checker.DeepEquals, upsert1stWanted)
	c.Assert(upsert2nd, checker.DeepEquals, upsert2ndWanted)
	c.Assert(upsert3rd, checker.DeepEquals, upsert3rdWanted)
	c.Assert(del1st, checker.DeepEquals, del1stWanted)
	c.Assert(del2nd, checker.DeepEquals, del2ndWanted)
}
