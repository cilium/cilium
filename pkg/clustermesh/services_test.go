// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests && integration_tests

package clustermesh

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	. "gopkg.in/check.v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/defaults"
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
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

var etcdConfig = []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

func (s *ClusterMeshServicesTestSuite) prepareServiceUpdate(clusterSuffix, backendIP, portName, port string) (string, string) {
	return "cilium/state/services/v1/" + s.randomName + clusterSuffix + "/default/foo",
		`{"cluster":"` + s.randomName + clusterSuffix + `","namespace":"default","name":"foo","frontends":{"172.20.0.177":{"port":{"protocol":"TCP","port":80}}},"backends":{"` + backendIP + `":{"` + portName + `":{"protocol":"TCP","port":` + port + `}}},"labels":{},"selector":{"name":"foo"},"shared":true,"includeExternal":true}`

}

type ClusterMeshServicesTestSuite struct {
	svcCache   k8s.ServiceCache
	testDir    string
	mesh       *ClusterMesh
	randomName string
}

var (
	_ = Suite(&ClusterMeshServicesTestSuite{})
)

func (s *ClusterMeshServicesTestSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")

	s.randomName = rand.RandomString()

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName)
	s.svcCache = k8s.NewServiceCache(fakeDatapath.NewNodeAddressing())
	identity.InitWellKnownIdentities(&fakeConfig.Config{})

	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	<-mgr.InitIdentityAllocator(nil, nil)
	dir, err := os.MkdirTemp("", "multicluster")
	s.testDir = dir
	c.Assert(err, IsNil)

	config1 := path.Join(dir, s.randomName+"1")
	err = os.WriteFile(config1, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config2 := path.Join(dir, s.randomName+"2")
	err = os.WriteFile(config2, etcdConfig, 0644)
	c.Assert(err, IsNil)

	cm, err := NewClusterMesh(Configuration{
		Name:                  "test2",
		ConfigDirectory:       dir,
		NodeKeyCreator:        testNodeCreator,
		nodeObserver:          &testObserver{},
		ServiceMerger:         &s.svcCache,
		RemoteIdentityWatcher: mgr,
		IPCache:               ipcache.NewIPCache(nil),
	})
	c.Assert(err, IsNil)
	c.Assert(cm, Not(IsNil))

	s.mesh = cm

	// wait for both clusters to appear in the list of cm clusters
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 2
	}, 10*time.Second), IsNil)
}

func (s *ClusterMeshServicesTestSuite) TearDownTest(c *C) {
	if s.mesh != nil {
		s.mesh.Close()
		s.mesh.conf.RemoteIdentityWatcher.Close()
	}

	os.RemoveAll(s.testDir)
	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName)
	kvstore.Client().Close()
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
				"io.cilium/global-service": "true",
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
				"io.cilium/global-service": "true",
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
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("20.0.185.196")] != nil
	})

	k, v = s.prepareServiceUpdate("2", "90.0.185.196", "http", "8080")
	kvstore.Client().Set(context.TODO(), k, []byte(v))
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends[cmtypes.MustParseAddrCluster("80.0.185.196")] != nil &&
			event.Endpoints.Backends[cmtypes.MustParseAddrCluster("90.0.185.196")] != nil
	})

	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName+"1")
	// The observer will have a defaults.NodeDeleteDelay time before it receives
	// the event. For this reason we will trigger the delete events sequentially
	// and only do the assertion in the end. This way we wait 30seconds for the
	// test to complete instead of 30+30 seconds.
	time.Sleep(2 * time.Second)
	kvstore.Client().DeletePrefix(context.TODO(), "cilium/state/services/v1/"+s.randomName+"2")

	s.expectEvent(c, k8s.UpdateService, svcID, nil)
	s.expectEvent(c, k8s.DeleteService, svcID, nil)

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
