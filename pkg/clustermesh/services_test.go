// Copyright 2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *ClusterMeshTestSuite) TestClusterMeshServices(c *C) {
	kvstore.SetupDummy("etcd")
	defer kvstore.Close()

	svcCache := k8s.NewServiceCache()

	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	cache.InitIdentityAllocator(&identityAllocatorOwnerMock{})

	dir, err := ioutil.TempDir("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	etcdConfig := []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

	config1 := path.Join(dir, "cluster1")
	err = ioutil.WriteFile(config1, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config2 := path.Join(dir, "cluster2")
	err = ioutil.WriteFile(config2, etcdConfig, 0644)
	c.Assert(err, IsNil)

	cm, err := NewClusterMesh(Configuration{
		Name:            "test2",
		ConfigDirectory: dir,
		NodeKeyCreator:  testNodeCreator,
		nodeObserver:    &testObserver{},
		ServiceMerger:   &svcCache,
	})
	c.Assert(err, IsNil)
	c.Assert(cm, Not(IsNil))

	// wait for both clusters to appear in the list of cm clusters
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 2
	}, 10*time.Second), IsNil)

	svcDef := `{"cluster":"cluster1","namespace":"default","name":"foo","frontends":{"172.20.0.177":{"port":{"protocol":"tcp","port":80}}},"backends":{"10.0.185.196":{"http":{"protocol":"tcp","port":80}}},"labels":{},"selector":{"name":"foo"}}`
	kvstore.Set("cilium/state/services/v1/cluster1/default/foo", []byte(svcDef))

	svcDef = `{"cluster":"cluster2","namespace":"default","name":"foo","frontends":{"172.20.0.177":{"port":{"protocol":"tcp","port":80}}},"backends":{"20.0.185.196":{"http2":{"protocol":"tcp","port":90}}},"labels":{},"selector":{"name":"foo"}}`
	kvstore.Set("cilium/state/services/v1/cluster2/default/foo", []byte(svcDef))

	k8sSvc := &v1.Service{
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
	}

	svcID := svcCache.UpdateService(k8sSvc)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, Equals, k8s.UpdateService)
		c.Assert(event.ID, Equals, svcID)

		if event.Endpoints.Backends["10.0.185.196"] == nil {
			return false
		}

		if event.Endpoints.Backends["20.0.185.196"] == nil {
			return false
		}

		return true
	}, 2*time.Second), IsNil)

	kvstore.DeletePrefix("cilium/state/services/v1/cluster1")
	kvstore.DeletePrefix("cilium/state/services/v1/cluster2")

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, Equals, k8s.UpdateService)
		c.Assert(event.ID, Equals, svcID)

		// One of the backends must have been deleted already
		if event.Endpoints.Backends["10.0.185.196"] != nil && event.Endpoints.Backends["20.0.185.196"] != nil {
			return false
		}

		return true
	}, 2*time.Second), IsNil)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, Equals, k8s.UpdateService)
		c.Assert(event.ID, Equals, svcID)
		// Both backends must be gone
		c.Assert(event.Endpoints.Backends["10.0.185.196"], IsNil)
		c.Assert(event.Endpoints.Backends["20.0.185.196"], IsNil)
		return true
	}, 2*time.Second), IsNil)

	cm.Close()
}
