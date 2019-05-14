// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package clustermesh

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var etcdConfig = []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

func (s *ClusterMeshServicesTestSuite) prepareServiceUpdate(clusterSuffix, backendIP, portName, port string) (string, []byte) {
	return "cilium/state/services/v1/" + s.randomName + clusterSuffix + "/default/foo",
		[]byte(`{"cluster":"` + s.randomName + clusterSuffix + `","namespace":"default","name":"foo","frontends":{"172.20.0.177":{"port":{"protocol":"TCP","port":80}}},"backends":{"` + backendIP + `":{"` + portName + `":{"protocol":"TCP","port":` + port + `}}},"labels":{},"selector":{"name":"foo"}}`)

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

	s.randomName = testutils.RandomRune()

	kvstore.DeletePrefix("cilium/state/services/v1/" + s.randomName)
	s.svcCache = k8s.NewServiceCache()
	identity.InitWellKnownIdentities()
	cache.InitIdentityAllocator(&identityAllocatorOwnerMock{})
	dir, err := ioutil.TempDir("", "multicluster")
	s.testDir = dir
	c.Assert(err, IsNil)

	config1 := path.Join(dir, s.randomName+"1")
	err = ioutil.WriteFile(config1, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config2 := path.Join(dir, s.randomName+"2")
	err = ioutil.WriteFile(config2, etcdConfig, 0644)
	c.Assert(err, IsNil)

	cm, err := NewClusterMesh(Configuration{
		Name:            "test2",
		ConfigDirectory: dir,
		NodeKeyCreator:  testNodeCreator,
		nodeObserver:    &testObserver{},
		ServiceMerger:   &s.svcCache,
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
	}

	cache.Close()

	os.RemoveAll(s.testDir)
	kvstore.DeletePrefix("cilium/state/services/v1/" + s.randomName)
	kvstore.Close()
}

func (s *ClusterMeshServicesTestSuite) expectEvent(c *C, action k8s.CacheAction, id k8s.ServiceID, fn func(event k8s.ServiceEvent) bool) {
	c.Assert(testutils.WaitUntil(func() bool {
		var event k8s.ServiceEvent
		select {
		case event = <-s.svcCache.Events:
		case <-time.After(time.Second * 10):
			c.Errorf("Timeout while waiting for event to be received")
			return false
		}

		c.Assert(event.Action, Equals, action)
		c.Assert(event.ID, Equals, id)

		if fn != nil {
			return fn(event)
		}

		return true
	}, 2*time.Second), IsNil)
}

func (s *ClusterMeshServicesTestSuite) TestClusterMeshServicesGlobal(c *C) {
	kvstore.Set(s.prepareServiceUpdate("1", "10.0.185.196", "http", "80"))
	kvstore.Set(s.prepareServiceUpdate("2", "20.0.185.196", "http2", "90"))

	k8sSvc := &types.Service{
		Service: &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "default",
				Annotations: map[string]string{
					"io.cilium/global-service": "true",
				},
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "127.0.0.1",
				Type:      v1.ServiceTypeClusterIP,
			},
		},
	}

	svcID := s.svcCache.UpdateService(k8sSvc)

	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends["10.0.185.196"] != nil &&
			event.Endpoints.Backends["20.0.185.196"] != nil
	})

	k8sEndpoints := &types.Endpoints{
		Endpoints: &v1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "default",
			},
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{{IP: "30.0.185.196"}},
					Ports: []v1.EndpointPort{
						{
							Name:     "http",
							Port:     100,
							Protocol: v1.ProtocolTCP,
						},
					},
				},
			},
		},
	}

	s.svcCache.UpdateEndpoints(k8sEndpoints)
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends["30.0.185.196"] != nil
	})

	s.svcCache.DeleteEndpoints(k8sEndpoints)
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends["30.0.185.196"] == nil
	})

	kvstore.DeletePrefix("cilium/state/services/v1/" + s.randomName + "1")
	s.expectEvent(c, k8s.UpdateService, svcID, nil)

	kvstore.DeletePrefix("cilium/state/services/v1/" + s.randomName + "2")
	s.expectEvent(c, k8s.DeleteService, svcID, nil)
}

func (s *ClusterMeshServicesTestSuite) TestClusterMeshServicesUpdate(c *C) {
	kvstore.Set(s.prepareServiceUpdate("1", "10.0.185.196", "http", "80"))
	kvstore.Set(s.prepareServiceUpdate("2", "20.0.185.196", "http2", "90"))

	k8sSvc := &types.Service{
		Service: &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "default",
				Annotations: map[string]string{
					"io.cilium/global-service": "true",
				},
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "127.0.0.1",
				Type:      v1.ServiceTypeClusterIP,
			},
		},
	}

	svcID := s.svcCache.UpdateService(k8sSvc)

	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends["10.0.185.196"]["http"].Equals(
			loadbalancer.NewL4Addr(loadbalancer.TCP, 80)) &&
			event.Endpoints.Backends["20.0.185.196"]["http2"].Equals(
				loadbalancer.NewL4Addr(loadbalancer.TCP, 90))
	})

	kvstore.Set(s.prepareServiceUpdate("1", "80.0.185.196", "http", "8080"))
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends["80.0.185.196"] != nil &&
			event.Endpoints.Backends["20.0.185.196"] != nil
	})

	kvstore.Set(s.prepareServiceUpdate("2", "90.0.185.196", "http", "8080"))
	s.expectEvent(c, k8s.UpdateService, svcID, func(event k8s.ServiceEvent) bool {
		return event.Endpoints.Backends["80.0.185.196"] != nil &&
			event.Endpoints.Backends["90.0.185.196"] != nil
	})

	kvstore.DeletePrefix("cilium/state/services/v1/" + s.randomName + "1")
	s.expectEvent(c, k8s.UpdateService, svcID, nil)

	kvstore.DeletePrefix("cilium/state/services/v1/" + s.randomName + "2")
	s.expectEvent(c, k8s.DeleteService, svcID, nil)
}

func (s *ClusterMeshServicesTestSuite) TestClusterMeshServicesNonGlobal(c *C) {
	kvstore.Set(s.prepareServiceUpdate("1", "10.0.185.196", "http", "80"))
	kvstore.Set(s.prepareServiceUpdate("2", "20.0.185.196", "http2", "90"))

	k8sSvc := &types.Service{
		Service: &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "default",
				// shared annotation is NOT set
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "127.0.0.1",
				Type:      v1.ServiceTypeClusterIP,
			},
		},
	}

	s.svcCache.UpdateService(k8sSvc)

	time.Sleep(100 * time.Millisecond)
	select {
	case event := <-s.svcCache.Events:
		c.Errorf("Unexpected service event received: %+v", event)
	default:
	}
}
