// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	"github.com/cilium/cilium/pkg/rand"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

var etcdConfig = []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

func (s *ClusterMeshServicesTestSuite) prepareServiceUpdate(clusterSuffix, backendIP, portName, port string) (string, string) {
	return "cilium/state/services/v1/" + s.randomName + clusterSuffix + "/default/foo",
		`{"cluster":"` + s.randomName + clusterSuffix + `","namespace":"default","name":"foo","frontends":{"172.20.0.177":{"port":{"protocol":"TCP","port":80}}},"backends":{"` + backendIP + `":{"` + portName + `":{"protocol":"TCP","port":` + port + `}}},"labels":{},"selector":{"name":"foo"},"shared":true,"includeExternal":true}`

}

type ClusterMeshServicesTestSuite struct {
	svcCache   *k8s.ServiceCache
	testDir    string
	mesh       *ClusterMesh
	randomName string
}

var _ = Suite(&ClusterMeshServicesTestSuite{})

func (s *ClusterMeshServicesTestSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (s *ClusterMeshServicesTestSuite) SetUpTest(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kvstore.SetupDummy("etcd")

	s.randomName = rand.RandomString()
	clusterName1 := s.randomName + "1"
	clusterName2 := s.randomName + "2"

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName)
	s.svcCache = k8s.NewServiceCache(fakeDatapath.NewNodeAddressing())
	identity.InitWellKnownIdentities(&fakeConfig.Config{})

	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	<-mgr.InitIdentityAllocator(nil)
	dir, err := os.MkdirTemp("", "multicluster")
	s.testDir = dir
	c.Assert(err, IsNil)

	for i, cluster := range []string{clusterName1, clusterName2} {
		config := cmtypes.CiliumClusterConfig{
			ID: uint32(i),
		}
		err := SetClusterConfig(ctx, cluster, &config, kvstore.Client())
		c.Assert(err, IsNil)
	}

	config1 := path.Join(dir, clusterName1)
	err = os.WriteFile(config1, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config2 := path.Join(dir, clusterName2)
	err = os.WriteFile(config2, etcdConfig, 0644)
	c.Assert(err, IsNil)

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: ctx,
	})
	defer ipc.Shutdown()

	s.mesh = NewClusterMesh(hivetest.Lifecycle(c), Configuration{
		Config: Config{ClusterMeshConfig: dir},

		ClusterIDName:         types.ClusterIDName{ClusterID: 255, ClusterName: "test2"},
		NodeKeyCreator:        testNodeCreator,
		NodeObserver:          &testObserver{},
		ServiceMerger:         s.svcCache,
		RemoteIdentityWatcher: mgr,
		IPCache:               ipc,
	})
	c.Assert(s.mesh, Not(IsNil))

	// wait for both clusters to appear in the list of cm clusters
	c.Assert(testutils.WaitUntil(func() bool {
		return s.mesh.NumReadyClusters() == 2
	}, 10*time.Second), IsNil)
}

func (s *ClusterMeshServicesTestSuite) TearDownTest(c *C) {
	os.RemoveAll(s.testDir)
	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName)
	kvstore.Client().Close(context.TODO())
}

func (s *ClusterMeshServicesTestSuite) expectEvent(c *C, action k8s.CacheAction, id k8s.ServiceID, fn func(event k8s.ServiceEvent) bool) {
	c.Assert(testutils.WaitUntil(func() bool {
		var event k8s.ServiceEvent
		select {
		case event = <-s.svcCache.Events:
		case <-time.After(defaults.NodeDeleteDelay + time.Second*10):
			c.Errorf("Timeout while waiting for event to be received")
			return false
		}
		defer event.SWG.Done()

		c.Assert(event.Action, Equals, action)
		c.Assert(event.ID, Equals, id)

		if fn != nil {
			return fn(event)
		}

		return true
	}, 2*time.Second), IsNil)
}

func (s *ClusterMeshServicesTestSuite) TestClusterMeshServicesGlobal(c *C) {
	k, v := s.prepareServiceUpdate("1", "10.0.185.196", "http", "80")
	kvstore.Client().Set(context.TODO(), k, []byte(v))
	k, v = s.prepareServiceUpdate("2", "20.0.185.196", "http2", "90")
	kvstore.Client().Set(context.TODO(), k, []byte(v))

	swgSvcs := lock.NewStoppableWaitGroup()
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
			Annotations: map[string]string{
				"service.cilium.io/global": "true",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	svcID := s.svcCache.UpdateService(k8sSvc, swgSvcs)

	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("20.0.185.196")] != nil
	})

	k8sEndpoints := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "30.0.185.196"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http",
						Port:     100,
						Protocol: slim_corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	swgEps := lock.NewStoppableWaitGroup()
	s.svcCache.UpdateEndpoints(k8sEndpoints, swgEps)
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("30.0.185.196")] != nil
	})

	s.svcCache.DeleteEndpoints(k8sEndpoints, swgEps)
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("30.0.185.196")] == nil
	})

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName+"1")
	s.expectEvent(c, k8s.UpdateService, svcID, nil)

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName+"2")
	s.expectEvent(c, k8s.DeleteService, svcID, nil)

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), IsNil)
}

func (s *ClusterMeshServicesTestSuite) TestClusterMeshServicesUpdate(c *C) {
	k, v := s.prepareServiceUpdate("1", "10.0.185.196", "http", "80")
	kvstore.Client().Set(context.TODO(), k, []byte(v))
	k, v = s.prepareServiceUpdate("2", "20.0.185.196", "http2", "90")
	kvstore.Client().Set(context.TODO(), k, []byte(v))

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
			Annotations: map[string]string{
				"service.cilium.io/global": "true",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := s.svcCache.UpdateService(k8sSvc, swgSvcs)

	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.185.196")].Ports["http"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 80)) &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("20.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("20.0.185.196")].Ports["http2"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 90))
	})

	k, v = s.prepareServiceUpdate("1", "80.0.185.196", "http", "8080")
	kvstore.Client().Set(context.TODO(), k, []byte(v))
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("80.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("80.0.185.196")].Ports["http"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)) &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("20.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("20.0.185.196")].Ports["http2"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 90))
	})

	k, v = s.prepareServiceUpdate("2", "90.0.185.196", "http", "8080")
	kvstore.Client().Set(context.TODO(), k, []byte(v))
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("80.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("80.0.185.196")].Ports["http"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 8080)) &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("90.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("90.0.185.196")].Ports["http"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 8080))
	})

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName+"1")
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("90.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("90.0.185.196")].Ports["http"].DeepEqual(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 8080))
	})

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName+"2")
	s.expectEvent(c, k8s.DeleteService, svcID, func(event k8s.ServiceEvent) bool {
		return len(event.Endpoints.Backends) == 0
	})

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)
}

func (s *ClusterMeshServicesTestSuite) TestClusterMeshServicesNonGlobal(c *C) {
	k, v := s.prepareServiceUpdate("1", "10.0.185.196", "http", "80")
	kvstore.Client().Set(context.TODO(), k, []byte(v))
	k, v = s.prepareServiceUpdate("2", "20.0.185.196", "http2", "90")
	kvstore.Client().Set(context.TODO(), k, []byte(v))

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
			// shared annotation is NOT set
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	s.svcCache.UpdateService(k8sSvc, swgSvcs)

	time.Sleep(100 * time.Millisecond)
	select {
	case event := <-s.svcCache.Events:
		c.Errorf("Unexpected service event received: %+v", event)
	default:
	}

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)
}

type fakeServiceMerger struct {
	updated map[string]int
	deleted map[string]int
}

func (f *fakeServiceMerger) init() {
	f.updated = make(map[string]int)
	f.deleted = make(map[string]int)
}

func (f *fakeServiceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService, _ *lock.StoppableWaitGroup) {
	f.updated[service.String()]++
}

func (f *fakeServiceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService, _ *lock.StoppableWaitGroup) {
	f.deleted[service.String()]++
}

func (s *ClusterMeshServicesTestSuite) TestRemoteServiceObserver(c *C) {
	svc1 := serviceStore.ClusterService{Cluster: "remote", Namespace: "namespace", Name: "name", IncludeExternal: false, Shared: true}
	svc2 := serviceStore.ClusterService{Cluster: "remote", Namespace: "namespace", Name: "name"}
	cache := newGlobalServiceCache("cluster", "node")
	merger := fakeServiceMerger{}

	observer := remoteServiceObserver{
		remoteCluster: &remoteCluster{
			mesh: &ClusterMesh{
				globalServices: cache,
				conf:           Configuration{ServiceMerger: &merger},
			},
		},
		swg: lock.NewStoppableWaitGroup(),
	}

	// Observe a new service update (for a non-shared service), and assert it is not added to the cache
	merger.init()
	observer.OnUpdate(&svc2)

	c.Assert(merger.updated[svc1.String()], Equals, 0)
	c.Assert(cache.byName, HasLen, 0)

	// Observe a new service update (for a shared service), and assert it is correctly added to the cache
	merger.init()
	observer.OnUpdate(&svc1)

	c.Assert(merger.updated[svc1.String()], Equals, 1)
	c.Assert(merger.deleted[svc1.String()], Equals, 0)

	c.Assert(cache.byName, HasLen, 1)
	gs, ok := cache.byName[svc1.NamespaceServiceName()]
	c.Assert(ok, Equals, true)
	c.Assert(gs.clusterServices, HasLen, 1)
	found, ok := gs.clusterServices[svc1.Cluster]
	c.Assert(ok, Equals, true)
	c.Assert(found, checker.DeepEquals, &svc1)

	// Observe a new service deletion, and assert it is correctly removed from the cache
	merger.init()
	observer.OnDelete(&svc1)

	c.Assert(merger.updated[svc1.String()], Equals, 0)
	c.Assert(merger.deleted[svc1.String()], Equals, 1)
	c.Assert(cache.byName, HasLen, 0)

	// Observe two service updates in sequence (first shared, then non-shared),
	// and assert that at the end it is not present in the cache (equivalent to update, then delete).
	merger.init()
	observer.OnUpdate(&svc1)
	observer.OnUpdate(&svc2)

	c.Assert(merger.updated[svc1.String()], Equals, 1)
	c.Assert(merger.deleted[svc1.String()], Equals, 1)
	c.Assert(cache.byName, HasLen, 0)
}
