/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fake

import (
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
	internalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/core/internalversion"
)

type FakeCore struct {
	*testing.Fake
}

func (c *FakeCore) ComponentStatuses() internalversion.ComponentStatusInterface {
	return &FakeComponentStatuses{c}
}

func (c *FakeCore) ConfigMaps(namespace string) internalversion.ConfigMapInterface {
	return &FakeConfigMaps{c, namespace}
}

func (c *FakeCore) Endpoints(namespace string) internalversion.EndpointsInterface {
	return &FakeEndpoints{c, namespace}
}

func (c *FakeCore) Events(namespace string) internalversion.EventInterface {
	return &FakeEvents{c, namespace}
}

func (c *FakeCore) LimitRanges(namespace string) internalversion.LimitRangeInterface {
	return &FakeLimitRanges{c, namespace}
}

func (c *FakeCore) Namespaces() internalversion.NamespaceInterface {
	return &FakeNamespaces{c}
}

func (c *FakeCore) Nodes() internalversion.NodeInterface {
	return &FakeNodes{c}
}

func (c *FakeCore) PersistentVolumes() internalversion.PersistentVolumeInterface {
	return &FakePersistentVolumes{c}
}

func (c *FakeCore) PersistentVolumeClaims(namespace string) internalversion.PersistentVolumeClaimInterface {
	return &FakePersistentVolumeClaims{c, namespace}
}

func (c *FakeCore) Pods(namespace string) internalversion.PodInterface {
	return &FakePods{c, namespace}
}

func (c *FakeCore) PodTemplates(namespace string) internalversion.PodTemplateInterface {
	return &FakePodTemplates{c, namespace}
}

func (c *FakeCore) ReplicationControllers(namespace string) internalversion.ReplicationControllerInterface {
	return &FakeReplicationControllers{c, namespace}
}

func (c *FakeCore) ResourceQuotas(namespace string) internalversion.ResourceQuotaInterface {
	return &FakeResourceQuotas{c, namespace}
}

func (c *FakeCore) Secrets(namespace string) internalversion.SecretInterface {
	return &FakeSecrets{c, namespace}
}

func (c *FakeCore) Services(namespace string) internalversion.ServiceInterface {
	return &FakeServices{c, namespace}
}

func (c *FakeCore) ServiceAccounts(namespace string) internalversion.ServiceAccountInterface {
	return &FakeServiceAccounts{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeCore) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
