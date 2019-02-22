// Copyright 2017-2019 Authors of Cilium
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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	go_runtime "runtime"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeAddressing "github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioned"

	go_version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/api/networking/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func (ds *DaemonSuite) Test_missingK8sNetworkPolicyV1(c *C) {
	type args struct {
		m    versioned.Map
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				return args{
					repo: p1,
					m:    versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "repository is missing a policy",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
						},
					},
				})
				return m
			},
		},
		{
			name: "repository contains all policies",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				_, err := p1.Add(api.Rule{
					EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
					Labels: labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, "bar", labels.LabelSourceK8s),
						labels.NewLabel(k8sConst.PolicyLabelNamespace, "foo", labels.LabelSourceK8s)},
				})
				c.Assert(err, IsNil)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		got := ds.d.missingK8sNetworkPolicyV1(args.m)
		c.Assert(got, checker.DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingCNPv2(c *C) {
	uuid := types.UID("13bba160-ddca-13e8-b697-0800273b04ff")

	type args struct {
		m    versioned.Map
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				return args{
					repo: p1,
					m:    versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "repository is missing a policy",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v2.CiliumNetworkPolicy{
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
							Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v2.CiliumNetworkPolicy{
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
							Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
						},
					},
				})
				return m
			},
		},
		{
			name: "repository contains all policies",
			setupArgs: func() args {
				p1 := policy.NewPolicyRepository()
				_, err := p1.Add(api.Rule{
					EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
					Labels: utils.GetPolicyLabels(
						"foo", "bar", uuid,
						utils.ResourceTypeCiliumNetworkPolicy),
				})
				c.Assert(err, IsNil)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
							UID:       uuid,
						},
						Spec: &api.Rule{
							EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
							Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
						},
					},
				})

				return args{
					m:    m,
					repo: p1,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		got := ds.d.missingCNPv2(args.m)
		c.Assert(got, checker.DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingK8sPodV1(c *C) {
	defer endpointmanager.RemoveAll()
	type args struct {
		m     versioned.Map
		cache *ipcache.IPCache
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				return args{
					cache: ipcache.NewIPCache(),
					m:     versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "ipcache is missing a pod",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				if err := endpointmanager.Insert(endpointCreator(123, identity.NumericIdentity(1000))); err != nil {
					panic(err)
				}
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Status: core_v1.PodStatus{
							PodIP: "127.0.0.1",
						},
					},
				})

				return args{
					m:     m,
					cache: ipcache.NewIPCache(),
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Status: core_v1.PodStatus{
							PodIP: "127.0.0.1",
						},
					},
				})
				return m
			},
		},
		{
			name: "ipcache contains the pod but endpointmanager doesn't contain any endpoint that manages the pod. Should be no-op",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				if err := endpointmanager.Insert(endpointCreator(123, identity.NumericIdentity(1000))); err != nil {
					panic(err)
				}
				cache := ipcache.NewIPCache()
				cache.Upsert("127.0.0.1", net.ParseIP("127.0.0.2"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Status: core_v1.PodStatus{
							PodIP:  "127.0.0.1",
							HostIP: "127.0.0.2",
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "ipcache contains the pod and endpointmanager contains the endpoint that manages the pod but ep doesn't have all labels",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				ep := endpointCreator(123, identity.NumericIdentity(1000))
				ep.SetK8sPodName("foo")
				ep.SetK8sNamespace("bar")
				if err := endpointmanager.Insert(ep); err != nil {
					panic(err)
				}
				cache := ipcache.NewIPCache()
				cache.Upsert("127.0.0.1", net.ParseIP("127.0.0.2"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							Labels: map[string]string{
								"id.foo": "bar",
							},
						},
						Status: core_v1.PodStatus{
							PodIP:  "127.0.0.1",
							HostIP: "127.0.0.2",
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							Labels: map[string]string{
								"id.foo": "bar",
							},
						},
						Status: core_v1.PodStatus{
							PodIP:  "127.0.0.1",
							HostIP: "127.0.0.2",
						},
					},
				})
				return m
			},
		},
		{
			name: "ipcache contains the pod and endpointmanager contains the endpoint that manages the pod and have all labels",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				ep := endpointCreator(123, identity.NumericIdentity(1000))
				ep.OpLabels.OrchestrationIdentity = labels.Map2Labels(map[string]string{"foo": "bar"}, labels.LabelSourceK8s)
				ep.SetK8sPodName("foo")
				ep.SetK8sNamespace("bar")
				if err := endpointmanager.Insert(ep); err != nil {
					panic(err)
				}
				cache := ipcache.NewIPCache()
				cache.Upsert("127.0.0.1", net.ParseIP("127.0.0.2"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							Labels: map[string]string{
								"foo": "bar",
							},
						},
						Status: core_v1.PodStatus{
							PodIP:  "127.0.0.1",
							HostIP: "127.0.0.2",
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "ipcache contains the pod and endpointmanager contains the endpoint that manages the pod but ep has old pod labels",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				ep := endpointCreator(123, identity.NumericIdentity(1000))
				ep.OpLabels.OrchestrationIdentity = labels.Map2Labels(map[string]string{"foo": "bar"}, labels.LabelSourceK8s)
				ep.SetK8sPodName("foo")
				ep.SetK8sNamespace("bar")
				if err := endpointmanager.Insert(ep); err != nil {
					panic(err)
				}
				cache := ipcache.NewIPCache()
				cache.Upsert("127.0.0.1", net.ParseIP("127.0.0.2"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Status: core_v1.PodStatus{
							PodIP:  "127.0.0.1",
							HostIP: "127.0.0.2",
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Status: core_v1.PodStatus{
							PodIP:  "127.0.0.1",
							HostIP: "127.0.0.2",
						},
					},
				})
				return m
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ipcache.IPIdentityCache = args.cache
		got := missingK8sPodV1(args.m)
		c.Assert(got, checker.DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingK8sNodeV1(c *C) {
	defer ds.d.nodeDiscovery.Manager.DeleteAllNodes()
	prevClusterName := option.Config.ClusterName
	option.Config.ClusterName = "default"
	defer func() {
		option.Config.ClusterName = prevClusterName
	}()
	type args struct {
		m     versioned.Map
		cache *ipcache.IPCache
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				return args{
					cache: ipcache.NewIPCache(),
					m:     versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "ipcache is missing a node",
			setupArgs: func() args {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Annotations: map[string]string{
								annotation.CiliumHostIP: "127.0.0.1",
							},
						},
					},
				})

				return args{
					m:     m,
					cache: ipcache.NewIPCache(),
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Annotations: map[string]string{
								annotation.CiliumHostIP: "127.0.0.1",
							},
						},
					},
				})
				return m
			},
		},
		{
			name: "ipcache and the node package contains the node. Should be no-op",
			setupArgs: func() args {
				ds.d.nodeDiscovery.Manager.DeleteAllNodes()
				cache := ipcache.NewIPCache()
				cache.Upsert("172.20.0.1", net.ParseIP("172.20.0.2"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				ds.d.nodeDiscovery.Manager.NodeUpdated(node.Node{
					Name:    "foo",
					Cluster: "default",
					Source:  node.FromKubernetes,
					IPAddresses: []node.Address{
						{
							Type: nodeAddressing.NodeInternalIP,
							IP:   net.ParseIP("172.20.0.1"),
						},
					},
				})

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Annotations: map[string]string{
								annotation.CiliumHostIP: "172.20.0.1",
							},
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "node doesn't contain any cilium host IP. should be no-op",
			setupArgs: func() args {
				ds.d.nodeDiscovery.Manager.DeleteAllNodes()
				cache := ipcache.NewIPCache()
				cache.Upsert("127.0.0.1", net.ParseIP("127.0.0.2"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Labels: map[string]string{
								"foo": "bar",
							},
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "ipcache contains the node but the CiliumHostIP is not the right one for the given nodeIP",
			setupArgs: func() args {
				ds.d.nodeDiscovery.Manager.DeleteAllNodes()
				cache := ipcache.NewIPCache()
				cache.Upsert("172.20.9.1", net.ParseIP("172.20.1.1"), ipcache.Identity{
					ID:     identity.ReservedIdentityInit,
					Source: ipcache.FromKubernetes,
				})
				ds.d.nodeDiscovery.Manager.NodeUpdated(node.Node{
					Name:    "bar",
					Source:  node.FromAgentLocal,
					Cluster: "default",
					IPAddresses: []node.Address{
						{
							Type: nodeAddressing.NodeInternalIP,
							IP:   net.ParseIP("172.20.0.1"),
						},
					},
				})
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "bar",
							Annotations: map[string]string{
								annotation.CiliumHostIP: "172.20.9.1",
							},
						},
					},
				})

				return args{
					m:     m,
					cache: cache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "bar",
							Annotations: map[string]string{
								annotation.CiliumHostIP: "172.20.9.1",
							},
						},
					},
				})
				return m
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ipcache.IPIdentityCache = args.cache
		got := ds.d.missingK8sNodeV1(args.m)
		c.Assert(got, checker.DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingK8sNamespaceV1(c *C) {
	type args struct {
		m versioned.Map
	}

	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				return args{
					m: versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "endpointmanager doesn't contain any endpoint that is part of that namespace. Should be no-op",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				ep := endpointCreator(123, identity.NumericIdentity(1000))
				if err := endpointmanager.Insert(ep); err != nil {
					panic(err)
				}
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: "bar",
						},
					},
				})

				return args{
					m: m,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "endpointmanager contains the endpoint that is part of that namespace but ep doesn't have all labels",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				ep := endpointCreator(124, identity.NumericIdentity(1000))
				ep.SetK8sNamespace("foo")
				if err := endpointmanager.Insert(ep); err != nil {
					panic(err)
				}
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Labels: map[string]string{
								"id.foo": "bar",
							},
						},
					},
				})

				return args{
					m: m,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Labels: map[string]string{
								"id.foo": "bar",
							},
						},
					},
				})
				return m
			},
		},
		{
			name: "endpointmanager contains the endpoint that is part of that namespace and have all labels",
			setupArgs: func() args {
				endpointmanager.RemoveAll()
				ep := endpointCreator(125, identity.NumericIdentity(1000))
				ep.OpLabels.OrchestrationIdentity = labels.Map2Labels(
					map[string]string{policy.JoinPath(k8sConst.PodNamespaceMetaLabels, "id.foo"): "bar"},
					labels.LabelSourceK8s)
				ep.SetK8sNamespace("foo")
				if err := endpointmanager.Insert(ep); err != nil {
					panic(err)
				}
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &core_v1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
							Labels: map[string]string{
								"id.foo": "bar",
							},
						},
					},
				})

				return args{
					m: m,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		got := ds.d.missingK8sNamespaceV1(args.m)
		c.Assert(got, checker.DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_addCiliumNetworkPolicyV2(c *C) {
	// ciliumV2Store cache.Store, oldRules api.Rules, cnp *cilium_v2.CiliumNetworkPolicy

	uuid := types.UID("13bba160-ddca-13e8-b697-0800273b04ff")
	type args struct {
		ciliumV2Store cache.Store
		cnp           *v2.CiliumNetworkPolicy
		repo          *policy.Repository
	}
	type wanted struct {
		err  error
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
	}{
		{
			name: "simple policy added",
			setupArgs: func() args {
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "db",
							Namespace: "production",
							UID:       uuid,
						},
						Spec: &api.Rule{
							EndpointSelector: api.EndpointSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "cluster-1",
									},
								},
							},
						},
					},
					repo: policy.NewPolicyRepository(),
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule with user labels and update it without user labels, all other rules should be deleted",
			setupArgs: func() args {
				r := policy.NewPolicyRepository()
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...)
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      lbls,
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "db",
							Namespace: "production",
							UID:       uuid,
						},
						Spec: &api.Rule{
							EndpointSelector: api.EndpointSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "cluster-1",
									},
								},
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule without user labels and update it with user labels, all other rules should be deleted",
			setupArgs: func() args {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "db",
							Namespace: "production",
							UID:       uuid,
						},
						Spec: &api.Rule{
							EndpointSelector: api.EndpointSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "cluster-1",
									},
								},
							},
							Labels: labels.ParseLabelArray("foo=bar"),
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...)
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      lbls,
						Description: "",
					},
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule policy installed with multiple rules and apply an empty spec should delete all rules installed",
			setupArgs: func() args {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress: []api.IngressRule{
							{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"env": "cluster-1",
												labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
											},
										},
									},
								},
							},
						},
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &v2.CiliumNetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "db",
							Namespace: "production",
							UID:       uuid,
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository()
				r.AddList(api.Rules{})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
	}
	var err error
	k8sServerVer, err = go_version.NewVersion("1.13")
	c.Assert(err, IsNil)
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		err := ds.d.addCiliumNetworkPolicyV2(&fake.Clientset{}, args.ciliumV2Store, args.cnp)
		c.Assert(err, checker.DeepEquals, want.err, Commentf("Test name: %q", tt.name))
		c.Assert(ds.d.policy.GetRulesList().Policy, checker.DeepEquals, want.repo.GetRulesList().Policy, Commentf("Test name: %q", tt.name))
	}
}

type K8sSuite struct{}

var _ = Suite(&K8sSuite{})

func (k *K8sSuite) SetUpSuite(c *C) {
	if true {
		logging.DefaultLogger.SetLevel(logrus.PanicLevel)
		log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)
	}
	if os.Getenv("INTEGRATION") != "" {
		if k8sConfigPath := os.Getenv("KUBECONFIG"); k8sConfigPath == "" {
			k8s.Configure("", "/var/lib/cilium/cilium.kubeconfig")
		} else {
			k8s.Configure("", k8sConfigPath)
		}
		restConfig, err := k8s.CreateConfig()
		c.Assert(err, IsNil)
		apiextensionsclientset, err := apiextensionsclient.NewForConfig(restConfig)
		c.Assert(err, IsNil)
		err = v2.CreateCustomResourceDefinitions(apiextensionsclientset)
		c.Assert(err, IsNil)
	}
}

func testUpdateCNPNodeStatusK8s(integrationTest bool, k8sVersion string, c *C) {
	// For k8s <v1.13
	// the unit tests will perform 3 actions, A, B and C where:
	// A-1.10) update k8s1 node status
	//    this will make 1 attempt as it is the first node populating status
	// B-1.10) update k8s2 node status
	//    this will make 3 attempts
	// C-1.10) update k8s1 node status with revision=2 and enforcing=false
	//    this will make 3 attempts
	// the code paths for A-1.10, B-1.10 and C-1.10 can be found in the comments

	// For k8s >=v1.13
	// the unit tests will perform 3 actions, A, B and C where:
	// A-1.13) update k8s1 node status
	//         this will make 1 attempt as it is the first node populating status
	// B-1.13) update k8s2 node status
	//         this will make 2 attempts
	// C-1.13) update k8s1 node status with revision=2 and enforcing=false
	//         this will make 2 attempts
	// the code paths for A-1.13, B-1.13 and C-1.13 can be found in the comments

	var err error
	k8sServerVer, err = go_version.NewVersion(k8sVersion)
	c.Assert(err, IsNil)

	cnp := &v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CiliumNetworkPolicy",
			APIVersion: "cilium.io/v2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing-policy",
			Namespace: "default",
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			},
		},
	}

	wantedCNP := cnp.DeepCopy()

	wantedCNPS := v2.CiliumNetworkPolicyStatus{
		Nodes: map[string]v2.CiliumNetworkPolicyNodeStatus{
			"k8s1": {
				Enforcing:   true,
				Revision:    1,
				OK:          true,
				LastUpdated: v2.Timestamp{},
				Annotations: map[string]string{
					"foo":                            "bar",
					"i-will-disappear-in-2nd-update": "bar",
				},
			},
			"k8s2": {
				Enforcing:   true,
				Revision:    2,
				OK:          true,
				LastUpdated: v2.Timestamp{},
			},
		},
	}

	wantedCNP.Status = wantedCNPS

	var ciliumNPClient clientset.Interface
	if integrationTest {
		restConfig, err := k8s.CreateConfig()
		c.Assert(err, IsNil)
		ciliumNPClient, err = clientset.NewForConfig(restConfig)
		c.Assert(err, IsNil)
		cnp, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Create(cnp)
		c.Assert(err, IsNil)
		defer func() {
			err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Delete(cnp.GetName(), &metav1.DeleteOptions{})
			c.Assert(err, IsNil)
		}()
	} else {
		ciliumNPClientFake := &fake.Clientset{}
		ciliumNPClientFake.AddReactor("patch", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				pa := action.(k8sTesting.PatchAction)
				time.Sleep(1 * time.Millisecond)
				var receivedJsonPatch []jsonPatch
				err := json.Unmarshal(pa.GetPatch(), &receivedJsonPatch)
				c.Assert(err, IsNil)

				switch {
				case receivedJsonPatch[0].OP == "test" && receivedJsonPatch[0].Path == "/status":
					switch {
					case receivedJsonPatch[0].Value == nil:
						cnpns := receivedJsonPatch[1].Value.(map[string]interface{})
						nodes := cnpns["nodes"].(map[string]interface{})
						if nodes["k8s1"] == nil {
							// codepath B-1.10) and B-1.13) 1st attempt
							// This is an attempt from k8s2 so we need
							// to return an error because `/status` is not nil as
							// it was previously set by k8s1
							return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonInvalid}}
						}
						// codepath A-1.10), C-1.10), A-1.13) and C-1.13)
						n := nodes["k8s1"].(map[string]interface{})

						if n["localPolicyRevision"].(float64) == 2 {
							// codepath C-1.10) and C-1.13) 1st attempt
							// This is an attempt from k8s1 to update its status
							// again, return an error because `/status` is not nil
							// as it was previously set by k8s1
							return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonInvalid}}
						}
						// codepath A-1.10) and A-1.13)

						// Ignore lastUpdated timestamp as it will mess up with
						// the deepequals
						n["lastUpdated"] = "0001-01-01T00:00:00Z"

						// Remove k8s2 from the nodes status.
						cnpsK8s1 := wantedCNPS.DeepCopy()
						delete(cnpsK8s1.Nodes, "k8s2")
						createStatusAndNodePatch := []jsonPatch{
							{
								OP:    "test",
								Path:  "/status",
								Value: nil,
							},
							{
								OP:    "add",
								Path:  "/status",
								Value: cnpsK8s1,
							},
						}
						expectedJSONPatchBytes, err := json.Marshal(createStatusAndNodePatch)
						c.Assert(err, IsNil)
						var expectedJSONPatch []jsonPatch
						err = json.Unmarshal(expectedJSONPatchBytes, &expectedJSONPatch)
						c.Assert(err, IsNil)

						c.Assert(receivedJsonPatch, checker.DeepEquals, expectedJSONPatch)

						// Copy the status the the cnp so we can compare it at
						// the end of this test to make sure everything is alright.
						cnp.Status = *cnpsK8s1
						return true, cnp, nil

					case receivedJsonPatch[0].Value != nil:
						// codepath B-1.10) and C-1.10) 2nd attempt
						// k8s1 and k8s2 knows that `/status` exists and was created
						// by a different node so he just needs to add itself to
						// the list of nodes.
						// "Unfortunately" the list of node is not-empty so
						// the test value of `/status` needs to fail
						c.Assert(cnp.Status.Nodes, Not(Equals), 0)
						return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonInvalid}}
					}
				case receivedJsonPatch[0].OP == "replace":
					// codepath B-1.13) and C-1.13) 2nd attempt
					fallthrough
				case receivedJsonPatch[0].OP == "add":
					cnpns := receivedJsonPatch[0].Value.(map[string]interface{})
					// codepath B-1.10) and C-1.10) 3rd attempt
					// k8s2 knows that `/status` exists and was created
					// by a different node so he just needs to add itself to
					// the list of nodes.
					if len(cnp.Status.Nodes) == 1 {
						// codepath B-1.10) 3rd attempt
						// k8s1 knows that `/status` exists and was populated
						// by a different node so he just needs to add (update)
						// itself to the list of nodes.
						// Ignore lastUpdated timestamp as it will mess up with
						// the deepequals
						cnpns["lastUpdated"] = "0001-01-01T00:00:00Z"

						// Remove k8s1 from the nodes status.
						cnpsK8s2 := wantedCNPS.DeepCopy()
						delete(cnpsK8s2.Nodes, "k8s1")

						createStatusAndNodePatch := []jsonPatch{
							{
								OP:    receivedJsonPatch[0].OP,
								Path:  "/status/nodes/k8s2",
								Value: cnpsK8s2.Nodes["k8s2"],
							},
						}
						expectedJSONPatchBytes, err := json.Marshal(createStatusAndNodePatch)
						c.Assert(err, IsNil)
						var expectedJSONPatch []jsonPatch
						err = json.Unmarshal(expectedJSONPatchBytes, &expectedJSONPatch)
						c.Assert(err, IsNil)

						c.Assert(receivedJsonPatch, checker.DeepEquals, expectedJSONPatch)

						cnp.Status.Nodes["k8s2"] = cnpsK8s2.Nodes["k8s2"]
						return true, cnp, nil
					}
					// codepath C-1.10) 3rd attempt
					cnpns["lastUpdated"] = "0001-01-01T00:00:00Z"

					// Remove k8s2 from the nodes status.
					cnpsK8s1 := wantedCNPS.DeepCopy()
					delete(cnpsK8s1.Nodes, "k8s2")
					// This update from k8s1 should have enforcing=false and
					// revision=2
					nWanted := cnpsK8s1.Nodes["k8s1"]
					nWanted.Revision = 2
					nWanted.Enforcing = false
					cnpsK8s1.Nodes["k8s1"] = nWanted

					createStatusAndNodePatch := []jsonPatch{
						{
							OP:    receivedJsonPatch[0].OP,
							Path:  "/status/nodes/k8s1",
							Value: nWanted,
						},
					}
					expectedJSONPatchBytes, err := json.Marshal(createStatusAndNodePatch)
					c.Assert(err, IsNil)
					var expectedJSONPatch []jsonPatch
					err = json.Unmarshal(expectedJSONPatchBytes, &expectedJSONPatch)
					c.Assert(err, IsNil)

					c.Assert(receivedJsonPatch, checker.DeepEquals, expectedJSONPatch)

					cnp.Status.Nodes["k8s1"] = cnpsK8s1.Nodes["k8s1"]
					return true, cnp, nil
				}
				// should never reach this point
				c.FailNow()
				return true, nil, fmt.Errorf("should not been called")
			})
		ciliumNPClient = ciliumNPClientFake
	}

	cnpns := wantedCNPS.Nodes["k8s1"]
	err = updateCNPNodeStatus(ciliumNPClient, cnp, cnpns.Enforcing, cnpns.OK, err, cnpns.Revision, cnpns.Annotations, "k8s1")
	c.Assert(err, IsNil)

	if integrationTest {
		cnp, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Get(cnp.GetName(), metav1.GetOptions{})
		c.Assert(err, IsNil)
	}

	cnpns = wantedCNPS.Nodes["k8s2"]
	err = updateCNPNodeStatus(ciliumNPClient, cnp, cnpns.Enforcing, cnpns.OK, err, cnpns.Revision, cnpns.Annotations, "k8s2")
	c.Assert(err, IsNil)

	if integrationTest {
		cnp, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Get(cnp.GetName(), metav1.GetOptions{})
		c.Assert(err, IsNil)

		// Ignore timestamps
		n := cnp.Status.Nodes["k8s1"]
		n.LastUpdated = v2.Timestamp{}
		cnp.Status.Nodes["k8s1"] = n
		n = cnp.Status.Nodes["k8s2"]
		n.LastUpdated = v2.Timestamp{}
		cnp.Status.Nodes["k8s2"] = n

		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	} else {
		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	}

	n := wantedCNP.Status.Nodes["k8s1"]
	n.Revision = 2
	n.Enforcing = false
	n.Annotations = map[string]string{
		"foo": "bar",
	}
	wantedCNP.Status.Nodes["k8s1"] = n

	cnpns = wantedCNPS.Nodes["k8s1"]
	err = updateCNPNodeStatus(ciliumNPClient, cnp, cnpns.Enforcing, cnpns.OK, err, cnpns.Revision, cnpns.Annotations, "k8s1")
	c.Assert(err, IsNil)

	if integrationTest {
		cnp, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Get(cnp.GetName(), metav1.GetOptions{})
		c.Assert(err, IsNil)

		// Ignore timestamps
		n := cnp.Status.Nodes["k8s1"]
		n.LastUpdated = v2.Timestamp{}
		cnp.Status.Nodes["k8s1"] = n
		n = cnp.Status.Nodes["k8s2"]
		n.LastUpdated = v2.Timestamp{}
		cnp.Status.Nodes["k8s2"] = n

		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	} else {
		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	}
}

func (k *K8sSuite) Test_updateCNPNodeStatus_1_10(c *C) {
	c.Skip("Test not available as implementation is not made")
	testUpdateCNPNodeStatusK8s(os.Getenv("INTEGRATION") != "", "1.10", c)
}

func (k *K8sSuite) Test_updateCNPNodeStatus_1_13(c *C) {
	testUpdateCNPNodeStatusK8s(os.Getenv("INTEGRATION") != "", "1.13", c)
}

func benchmarkCNPNodeStatusController(integrationTest bool, nNodes int, nParallelClients int, k8sVersion string, c *C) {
	if !integrationTest {
		c.Skip("Unit test only available with INTEGRATION=1")
	}

	var err error
	k8sServerVer, err = go_version.NewVersion(k8sVersion)
	c.Assert(err, IsNil)

	cnp := &v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CiliumNetworkPolicy",
			APIVersion: "cilium.io/v2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing-policy",
			Namespace: "default",
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
		},
	}

	restConfig, err := k8s.CreateConfig()
	c.Assert(err, IsNil)
	err = k8s.Init()
	c.Assert(err, IsNil)

	// One client per node
	ciliumNPClients := make([]clientset.Interface, nNodes)
	for i := range ciliumNPClients {
		ciliumNPClients[i], err = clientset.NewForConfig(restConfig)
		c.Assert(err, IsNil)
	}

	cnp, err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Create(cnp)
	c.Assert(err, IsNil)
	defer func() {
		err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Delete(cnp.GetName(), &metav1.DeleteOptions{})
		c.Assert(err, IsNil)
	}()

	var cnpStore cache.Store
	switch {
	case ciliumUpdateStatusVerConstr.Check(k8sServerVer):
		// k8s >= 1.13 does not require a store
	default:
		// TODO create a cache.Store per node
		si := informer.NewSharedInformerFactory(ciliumNPClients[0], 5*time.Minute)
		ciliumV2Controller := si.Cilium().V2().CiliumNetworkPolicies().Informer()
		cnpStore = ciliumV2Controller.GetStore()
		si.Start(wait.NeverStop)
		var exists bool
		// wait for the cnp created to be in the store
		for !exists {
			_, exists, err = cnpStore.Get(cnp)
			time.Sleep(100 * time.Millisecond)
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(nNodes)
	r := make(chan int, nNodes)
	for i := 0; i < nParallelClients; i++ {
		go func() {
			for i := range r {
				n := "k8s" + strconv.Itoa(i)
				err := cnpNodeStatusController(ciliumNPClients[i], cnpStore, cnp, uint64(i), log, nil, n)
				c.Assert(err, IsNil)
				wg.Done()
			}
		}()
	}

	start := time.Now()
	c.ResetTimer()
	for i := 0; i < nNodes; i++ {
		r <- i
	}
	wg.Wait()
	c.StopTimer()
	c.Logf("Test took: %s", time.Since(start))
}

func (k *K8sSuite) Benchmark_CNPNodeStatusController_1_10(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	benchmarkCNPNodeStatusController(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.10", c)
}

func (k *K8sSuite) Benchmark_CNPNodeStatusController_1_13(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	benchmarkCNPNodeStatusController(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.13", c)
}

func benchmarkUpdateCNPNodeStatus(integrationTest bool, nNodes int, nParallelClients int, k8sVersion string, c *C) {
	var err error
	k8sServerVer, err = go_version.NewVersion(k8sVersion)
	c.Assert(err, IsNil)
	cnp := &v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CiliumNetworkPolicy",
			APIVersion: "cilium.io/v2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing-policy",
			Namespace: "default",
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
			},
		},
	}

	// One client per node
	ciliumNPClients := make([]clientset.Interface, nNodes)
	if integrationTest {
		restConfig, err := k8s.CreateConfig()
		c.Assert(err, IsNil)
		for i := range ciliumNPClients {
			ciliumNPClients[i], err = clientset.NewForConfig(restConfig)
			c.Assert(err, IsNil)
		}
		cnp, err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Create(cnp)
		c.Assert(err, IsNil)
		defer func() {
			err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Delete(cnp.GetName(), &metav1.DeleteOptions{})
			c.Assert(err, IsNil)
		}()
	} else {
		ciliumNPClientFake := &fake.Clientset{}
		ciliumNPClientFake.AddReactor("patch", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				time.Sleep(1 * time.Millisecond)
				return true, cnp, nil
			})
		ciliumNPClientFake.AddReactor("get", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				time.Sleep(1 * time.Millisecond)
				return true, cnp, nil
			})
		ciliumNPClientFake.AddReactor("update", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				ua := action.(k8sTesting.UpdateAction)
				cnp := ua.GetObject().(*v2.CiliumNetworkPolicy)
				time.Sleep(1 * time.Millisecond)
				return true, cnp, nil
			})

		for i := range ciliumNPClients {
			ciliumNPClients[i] = ciliumNPClientFake
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(nNodes)
	r := make(chan int, nNodes)
	for i := 0; i < nParallelClients; i++ {
		go func() {
			for i := range r {
				n := "k8s" + strconv.Itoa(i)
				err := updateCNPNodeStatus(ciliumNPClients[i], cnp, true, true, nil, uint64(i), nil, n)
				c.Assert(err, IsNil)
				wg.Done()
			}
		}()
	}

	start := time.Now()
	c.ResetTimer()
	for i := 0; i < nNodes; i++ {
		r <- i
	}
	wg.Wait()
	c.StopTimer()
	c.Logf("Test took: %s", time.Since(start))
}

func (k *K8sSuite) Benchmark_UpdateCNPNodeStatus_1_10(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	benchmarkUpdateCNPNodeStatus(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.10", c)
}

func (k *K8sSuite) Benchmark_UpdateCNPNodeStatus_1_13(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	benchmarkUpdateCNPNodeStatus(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.13", c)
}
