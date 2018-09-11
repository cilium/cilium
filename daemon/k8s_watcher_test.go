// Copyright 2017 Authors of Cilium
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

package main

import (
	"time"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioned"

	. "gopkg.in/check.v1"
	"k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ds *DaemonSuite) TestK8sErrorLogTimeout(c *C) {
	errstr := "I am an error string"

	// ensure k8sErrMsg is empty for tests that use it
	k8sErrMsgMU.Lock()
	k8sErrMsg = map[string]time.Time{}
	k8sErrMsgMU.Unlock()

	// Returns true because it's the first time we see this message
	startTime := time.Now()
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, startTime), Equals, true)

	// Returns false because <= k8sErrLogTimeout time has passed
	noLogTime := startTime.Add(k8sErrLogTimeout)
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, noLogTime), Equals, false)

	// Returns true because k8sErrLogTimeout has passed
	shouldLogTime := startTime.Add(k8sErrLogTimeout).Add(time.Nanosecond)
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, shouldLogTime), Equals, true)
}

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
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}

func (ds *DaemonSuite) Test_missingCNPv2(c *C) {
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
					Labels:           labels.ParseLabelArray("k8s:name=bar", "k8s:namespace=bar"),
				})
				c.Assert(err, IsNil)

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
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo
		got := ds.d.missingCNPv2(args.m)
		c.Assert(got, DeepEquals, want, Commentf("Test name: %q", tt.name))
	}
}
