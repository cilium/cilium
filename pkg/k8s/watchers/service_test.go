// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"sort"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

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

func (f *fakeSvcManager) GetDeepCopyServiceByFrontend(frontend loadbalancer.L3n4Addr) (*loadbalancer.SVC, bool) {
	return nil, false
}

func (f *fakeSvcManager) UpsertService(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
	if f.OnUpsertService != nil {
		return f.OnUpsertService(p)
	}
	panic("OnUpsertService() was called and is not set!")
}

func newDB(t *testing.T) (*statedb.DB, statedb.Table[datapathTables.NodeAddress]) {
	db := statedb.New()
	nodeAddrs, err := datapathTables.NewNodeAddressTable()
	require.NoError(t, err)
	err = db.RegisterTable(nodeAddrs)
	require.NoError(t, err)

	txn := db.WriteTxn(nodeAddrs)
	for _, addr := range datapathTables.TestAddresses {
		nodeAddrs.Insert(txn, addr)
	}
	txn.Commit()

	return db, nodeAddrs
}

func Test_addK8sSVCs_ClusterIP(t *testing.T) {
	option.Config.LoadBalancerProtocolDifferentiation = true

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
				{
					Name:       "port-tcp-80",
					Protocol:   slim_corev1.ProtocolTCP,
					Port:       80,
					TargetPort: intstr.FromString("port-80-t"),
				},
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
					{
						Name:     "port-tcp-80",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
					},
					{
						Name:     "port-tcp-81",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     81,
					},
				},
			},
		},
	}

	lb1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	lb2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	lb3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)
	upsert1stWanted := map[string]loadbalancer.SVC{
		lb1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		lb2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		lb3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     81,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
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
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		lb2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		lb3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     81,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     81,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	del1stWanted := map[string]struct{}{
		lb1.Hash(): {},
		lb2.Hash(): {},
		lb3.Hash(): {},
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	del1st := map[string]struct{}{}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return p.Backends[i].AddrCluster.Less(p.Backends[j].AddrCluster)
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
			// TODO: doc
			if fe.Protocol == loadbalancer.ANY {
				return true, nil
			}

			del1st[fe.Hash()] = struct{}{}
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	db, nodeAddrs := newDB(t)
	k8sSvcCache := k8s.NewServiceCache(db, nodeAddrs)
	svcWatcher := &K8sServiceWatcher{
		k8sSvcCache: k8sSvcCache,
		svcManager:  svcManager,
	}

	go svcWatcher.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvcCache.UpdateService(k8sSvc, swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep1stApply), swg)
	// Running a 2nd update should also trigger a new upsert service
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)
	// Running a 3rd update should also not trigger anything because the
	// endpoints are the same
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)

	k8sSvcCache.DeleteService(k8sSvc, swg)

	swg.Stop()
	swg.Wait()

	require.Equal(t, len(upsert1stWanted)+len(upsert2ndWanted), svcUpsertManagerCalls)
	require.Equal(t, len(del1stWanted), svcDeleteManagerCalls)

	require.EqualValues(t, upsert1stWanted, upsert1st)
	require.EqualValues(t, upsert2ndWanted, upsert2nd)
	require.EqualValues(t, del1stWanted, del1st)
}

func TestChangeSVCPort(t *testing.T) {
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

	lb1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	lb2 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)
	upsertsWanted := []loadbalancer.SVC{
		{
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		{
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *lb2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	k8sSvcChanged := k8sSvc.DeepCopy()
	k8sSvcChanged.Spec.Ports[0].Port = 81

	upserts := []loadbalancer.SVC{}

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

	db, nodeAddrs := newDB(t)
	k8sSvcCache := k8s.NewServiceCache(db, nodeAddrs)
	svcWatcher := &K8sServiceWatcher{
		k8sSvcCache: k8sSvcCache,
		svcManager:  svcManager,
	}

	go svcWatcher.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvcCache.UpdateService(k8sSvc, swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep1stApply), swg)
	k8sSvcCache.UpdateService(k8sSvcChanged, swg)

	swg.Stop()
	swg.Wait()
	require.Equal(t, 2, svcUpsertManagerCalls) // Add and Update events
	require.EqualValues(t, upsertsWanted, upserts)
}

func Test_addK8sSVCs_NodePort(t *testing.T) {
	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	option.Config.LoadBalancerProtocolDifferentiation = true
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
				{
					Name:       "port-tcp-80",
					Protocol:   slim_corev1.ProtocolTCP,
					Port:       80,
					TargetPort: intstr.FromString("port-80-t"),
					NodePort:   18080,
				},
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
					{
						Name:     "port-tcp-80",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
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

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	ipv4NodePortAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4NodePortAddress)
	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4InternalAddress)

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4NodePortAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4InternalAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	nodePortIPs2 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4NodePortAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4InternalAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs2 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	nodePortIPs3 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4NodePortAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4InternalAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs3 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
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
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	for _, nodePort := range nodePortIPs1 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs3 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	del1stWanted := map[string]struct{}{
		clusterIP1.Hash(): {},
		clusterIP2.Hash(): {},
		clusterIP3.Hash(): {},
	}
	for _, nodePort := range append(nodePortIPs1, append(nodePortIPs2, nodePortIPs3...)...) {
		del1stWanted[nodePort.Hash()] = struct{}{}
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	del1st := map[string]struct{}{}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return p.Backends[i].AddrCluster.Less(p.Backends[j].AddrCluster)
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
			// TODO: doc
			if fe.Protocol == loadbalancer.ANY {
				return true, nil
			}

			del1st[fe.Hash()] = struct{}{}
			svcDeleteManagerCalls++
			return true, nil
		},
	}

	db, nodeAddrs := newDB(t)
	k8sSvcCache := k8s.NewServiceCache(db, nodeAddrs)
	svcWatcher := &K8sServiceWatcher{
		k8sSvcCache: k8sSvcCache,
		svcManager:  svcManager,
	}

	go svcWatcher.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvcCache.UpdateService(k8sSvc, swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep1stApply), swg)
	// Running a 2nd update should also trigger a new upsert service
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)
	// Running a 3rd update should also not trigger anything because the
	// endpoints are the same
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)

	k8sSvcCache.DeleteService(k8sSvc, swg)

	swg.Stop()
	swg.Wait()
	require.Equal(t, len(upsert1stWanted)+len(upsert2ndWanted), svcUpsertManagerCalls)
	require.Equal(t, len(del1stWanted), svcDeleteManagerCalls)

	require.EqualValues(t, upsert1stWanted, upsert1st)
	require.EqualValues(t, upsert2ndWanted, upsert2nd)
	require.EqualValues(t, del1stWanted, del1st)
}

func Test_addK8sSVCs_GH9576_1(t *testing.T) {
	// Adding service without any endpoints and later on modifying the service,
	// cilium should:
	// 1) delete the non existing services from the datapath.

	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	option.Config.LoadBalancerProtocolDifferentiation = true
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

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)
	ipv4NodePortAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4NodePortAddress)
	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4InternalAddress)

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4NodePortAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4InternalAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
	}
	nodePortIPs2 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4NodePortAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4InternalAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
	}

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	clusterIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 8083, loadbalancer.ScopeExternal, 0)

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
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

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0
	wantSvcUpsertManagerCalls := len(upsert1stWanted) + len(upsert2ndWanted)
	wantSvcDeleteManagerCalls := len(del1stWanted)

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return p.Backends[i].AddrCluster.Less(p.Backends[j].AddrCluster)
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

	db, nodeAddrs := newDB(t)
	k8sSvcCache := k8s.NewServiceCache(db, nodeAddrs)
	svcWatcher := &K8sServiceWatcher{
		k8sSvcCache: k8sSvcCache,
		svcManager:  svcManager,
	}

	go svcWatcher.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvcCache.UpdateService(k8sSvc1stApply, swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep1stApply), swg)

	k8sSvcCache.UpdateService(k8sSvc2ndApply, swg)

	swg.Stop()
	swg.Wait()
	require.Equal(t, wantSvcUpsertManagerCalls, svcUpsertManagerCalls)
	require.Equal(t, wantSvcDeleteManagerCalls, svcDeleteManagerCalls)

	require.EqualValues(t, upsert1stWanted, upsert1st)
	require.EqualValues(t, upsert2ndWanted, upsert2nd)
	require.EqualValues(t, del1stWanted, del1st)
}

func Test_addK8sSVCs_GH9576_2(t *testing.T) {
	// Adding service without any endpoints and later on modifying the service,
	// cilium should:
	// 1) delete the non existing endpoints from the datapath, i.e., updating
	//    services without any backend.

	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	option.Config.LoadBalancerProtocolDifferentiation = true
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

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)
	ipv4NodePortAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4NodePortAddress)
	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4InternalAddress)

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4NodePortAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4InternalAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
	}
	nodePortIPs2 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4NodePortAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4InternalAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
	}

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
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
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
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

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0
	wantSvcUpsertManagerCalls := len(upsert1stWanted) + len(upsert2ndWanted)
	wantSvcDeleteManagerCalls := len(del1stWanted)

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return p.Backends[i].AddrCluster.Less(p.Backends[j].AddrCluster)
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

	db, nodeAddrs := newDB(t)
	k8sSvcCache := k8s.NewServiceCache(db, nodeAddrs)
	svcWatcher := &K8sServiceWatcher{
		k8sSvcCache: k8sSvcCache,
		svcManager:  svcManager,
	}

	go svcWatcher.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvcCache.UpdateService(k8sSvc1stApply, swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep1stApply), swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)

	swg.Stop()
	swg.Wait()

	require.Equal(t, wantSvcUpsertManagerCalls, svcUpsertManagerCalls)
	require.Equal(t, wantSvcDeleteManagerCalls, svcDeleteManagerCalls)

	require.EqualValues(t, upsert1stWanted, upsert1st)
	require.EqualValues(t, upsert2ndWanted, upsert2nd)
	require.EqualValues(t, del1stWanted, del1st)
}

func Test_addK8sSVCs_ExternalIPs(t *testing.T) {
	enableNodePortBak := option.Config.EnableNodePort
	option.Config.EnableNodePort = true
	option.Config.LoadBalancerProtocolDifferentiation = true
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
				{
					Name:       "port-tcp-80",
					Protocol:   slim_corev1.ProtocolTCP,
					Port:       80,
					TargetPort: intstr.FromString("port-80-t"),
					NodePort:   18080,
				},
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
					{
						Name:     "port-tcp-80",
						Protocol: slim_corev1.ProtocolTCP,
						Port:     8081,
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

	ep2ndApply := ep1stApply.DeepCopy()
	ep2ndApply.Subsets[0].Addresses = append(
		ep2ndApply.Subsets[0].Addresses,
		slim_corev1.EndpointAddress{IP: "10.0.0.3"},
	)

	clusterIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 80, loadbalancer.ScopeExternal, 0)
	clusterIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("172.0.20.1"), 81, loadbalancer.ScopeExternal, 0)

	upsert1stWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	externalIP1 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("127.8.8.8"), 80, loadbalancer.ScopeExternal, 0)
	externalIP2 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("127.8.8.8"), 80, loadbalancer.ScopeExternal, 0)
	externalIP3 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("127.8.8.8"), 81, loadbalancer.ScopeExternal, 0)
	externalIP4 := loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("127.9.9.9"), 80, loadbalancer.ScopeExternal, 0)
	externalIP5 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("127.9.9.9"), 80, loadbalancer.ScopeExternal, 0)
	externalIP6 := loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("127.9.9.9"), 81, loadbalancer.ScopeExternal, 0)
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP1, externalIP4} {
		upsert1stWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP2, externalIP5} {
		upsert1stWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP3, externalIP6} {
		upsert1stWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	ipv4NodePortAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4NodePortAddress)
	ipv4InternalAddrCluster := cmtypes.MustAddrClusterFromIP(fakeTypes.IPv4InternalAddress)

	nodePortIPs1 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4NodePortAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.UDP, ipv4InternalAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs1 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	nodePortIPs2 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4NodePortAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4InternalAddrCluster, 18080, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs2 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	nodePortIPs3 := []*loadbalancer.L3n4AddrID{
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4NodePortAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
		loadbalancer.NewL3n4AddrID(loadbalancer.TCP, ipv4InternalAddrCluster, 18081, loadbalancer.ScopeExternal, 0),
	}
	for _, nodePort := range nodePortIPs3 {
		upsert1stWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	upsert2ndWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP1, externalIP4} {
		upsert2ndWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP2, externalIP5} {
		upsert2ndWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP3, externalIP6} {
		upsert2ndWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	for _, nodePort := range nodePortIPs1 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs3 {
		upsert2ndWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	upsert3rdWanted := map[string]loadbalancer.SVC{
		clusterIP1.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP1,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP2.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP2,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
		clusterIP3.Hash(): {
			Type:     loadbalancer.SVCTypeClusterIP,
			Frontend: *clusterIP3,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		},
	}

	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP1} {
		upsert3rdWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP2} {
		upsert3rdWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, externalIP := range []*loadbalancer.L3n4AddrID{externalIP3} {
		upsert3rdWanted[externalIP.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeExternalIPs,
			Frontend: *externalIP,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	for _, nodePort := range nodePortIPs1 {
		upsert3rdWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-udp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.UDP,
							Port:     8080,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs2 {
		upsert3rdWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-80",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}
	for _, nodePort := range nodePortIPs3 {
		upsert3rdWanted[nodePort.Hash()] = loadbalancer.SVC{
			Type:     loadbalancer.SVCTypeNodePort,
			Frontend: *nodePort,
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.2"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
				{
					FEPortName: "port-tcp-81",
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster("10.0.0.3"),
						L4Addr: loadbalancer.L4Addr{
							Protocol: loadbalancer.TCP,
							Port:     8081,
						},
					},
					Weight: loadbalancer.DefaultBackendWeight,
				},
			},
		}
	}

	del1stWanted := map[string]struct{}{
		externalIP4.Hash(): {},
		externalIP5.Hash(): {},
		externalIP6.Hash(): {},
	}
	del2ndWanted := map[string]struct{}{
		clusterIP1.Hash():  {},
		clusterIP2.Hash():  {},
		clusterIP3.Hash():  {},
		externalIP1.Hash(): {},
		externalIP2.Hash(): {},
		externalIP3.Hash(): {},
	}
	for _, nodePort := range append(nodePortIPs1, append(nodePortIPs2, nodePortIPs3...)...) {
		del2ndWanted[nodePort.Hash()] = struct{}{}
	}

	upsert1st := map[string]loadbalancer.SVC{}
	upsert2nd := map[string]loadbalancer.SVC{}
	upsert3rd := map[string]loadbalancer.SVC{}
	del1st := map[string]struct{}{}
	del2nd := map[string]struct{}{}

	svcUpsertManagerCalls, svcDeleteManagerCalls := 0, 0

	svcManager := &fakeSvcManager{
		OnUpsertService: func(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
			sort.Slice(p.Backends, func(i, j int) bool {
				return p.Backends[i].AddrCluster.Less(p.Backends[j].AddrCluster)
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
			// TODO: doc
			if fe.Protocol == loadbalancer.ANY {
				return true, nil
			}

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

	db, nodeAddrs := newDB(t)
	k8sSvcCache := k8s.NewServiceCache(db, nodeAddrs)
	svcWatcher := &K8sServiceWatcher{
		k8sSvcCache: k8sSvcCache,
		svcManager:  svcManager,
	}

	go svcWatcher.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvcCache.UpdateService(svc1stApply, swg)
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep1stApply), swg)
	// Running a 2nd update should also trigger a new upsert service
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)
	// Running a 3rd update should also not trigger anything because the
	// endpoints are the same
	k8sSvcCache.UpdateEndpoints(k8s.ParseEndpoints(ep2ndApply), swg)

	k8sSvcCache.UpdateService(svc2ndApply, swg)

	k8sSvcCache.DeleteService(svc1stApply, swg)

	swg.Stop()
	swg.Wait()
	require.Equal(t, len(upsert1stWanted)+len(upsert2ndWanted)+len(upsert3rdWanted), svcUpsertManagerCalls)
	require.Equal(t, len(del1stWanted)+len(del2ndWanted), svcDeleteManagerCalls)

	require.EqualValues(t, upsert1stWanted, upsert1st)
	require.EqualValues(t, upsert2ndWanted, upsert2nd)
	require.EqualValues(t, upsert3rdWanted, upsert3rd)
	require.EqualValues(t, del1stWanted, del1st)
	require.EqualValues(t, del2ndWanted, del2nd)
}
