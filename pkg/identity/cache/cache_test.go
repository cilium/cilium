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

package cache

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"

	. "gopkg.in/check.v1"
)

var (
	kvstoreLabels = labels.NewLabelsFromModel([]string{
		"k8s:app=etcd",
		"k8s:etcd_cluster=cilium-etcd",
		"k8s:io.cilium/app=etcd-operator",
		"k8s:io.kubernetes.pod.namespace=kube-system",
		"k8s:io.cilium.k8s.policy.serviceaccount=default",
		"k8s:io.cilium.k8s.policy.cluster=default",
	})
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IdentityCacheTestSuite struct{}

var _ = Suite(&IdentityCacheTestSuite{})

func (s *IdentityCacheTestSuite) TestLookupReservedIdentity(c *C) {
	mgr := NewCachingIdentityAllocator(newDummyOwner())
	<-mgr.InitIdentityAllocator(nil, nil)

	hostID := identity.GetReservedID("host")
	c.Assert(mgr.LookupIdentityByID(context.TODO(), hostID), Not(IsNil))

	id := mgr.LookupIdentity(context.TODO(), labels.NewLabelsFromModel([]string{"reserved:host"}))
	c.Assert(id, Not(IsNil))
	c.Assert(id.ID, Equals, hostID)

	worldID := identity.GetReservedID("world")
	c.Assert(mgr.LookupIdentityByID(context.TODO(), worldID), Not(IsNil))

	id = mgr.LookupIdentity(context.TODO(), labels.NewLabelsFromModel([]string{"reserved:world"}))
	c.Assert(id, Not(IsNil))
	c.Assert(id.ID, Equals, worldID)

	identity.InitWellKnownIdentities(&fakeConfig.Config{})

	id = mgr.LookupIdentity(context.TODO(), kvstoreLabels)
	c.Assert(id, Not(IsNil))
	c.Assert(id.ID, Equals, identity.ReservedCiliumKVStore)
}

func (s *IdentityCacheTestSuite) TestLookupReservedIdentityByLabels(c *C) {
	ni, err := identity.ParseNumericIdentity("129")
	c.Assert(err, IsNil)
	identity.AddUserDefinedNumericIdentity(ni, "kvstore")
	identity.AddReservedIdentity(ni, "kvstore")

	type args struct {
		lbls labels.Labels
	}
	tests := []struct {
		name string
		args args
		want *identity.Identity
	}{
		{
			name: "fixed-identity",
			args: args{
				lbls: labels.Labels{labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kvstore")},
			},
			want: identity.NewIdentity(ni, labels.Labels{"kvstore": labels.NewLabel("kvstore", "", labels.LabelSourceReserved)}),
		},
		{
			name: "non-existing-fixed-identity",
			args: args{
				lbls: labels.Labels{labels.LabelKeyFixedIdentity: labels.ParseLabel(labels.LabelKeyFixedIdentity + "=" + "kube-dns")},
			},
			want: nil,
		},
		{
			name: "reserved-identity",
			args: args{
				lbls: labels.Labels{labels.LabelSourceReserved: labels.NewLabel(labels.LabelSourceReservedKeyPrefix+"host", "", labels.LabelSourceReserved)},
			},
			want: identity.NewIdentity(identity.ReservedIdentityHost, labels.Labels{"host": labels.ParseLabel("reserved:host")}),
		},
		{
			name: "reserved-identity+other-labels",
			args: args{
				lbls: labels.Labels{
					labels.LabelSourceReserved: labels.ParseLabel("reserved:host"),
					"id.foo":                   labels.ParseLabel("id.foo"),
				},
			},
			want: identity.NewIdentity(identity.ReservedIdentityHost, labels.Labels{
				labels.LabelSourceReserved: labels.ParseLabel("reserved:host"),
				"id.foo":                   labels.ParseLabel("id.foo"),
			},
			),
		},
		{
			name: "well-known-kvstore",
			args: args{
				lbls: kvstoreLabels,
			},
			want: identity.NewIdentity(identity.ReservedCiliumKVStore, kvstoreLabels),
		},
	}

	for _, tt := range tests {
		got := identity.LookupReservedIdentityByLabels(tt.args.lbls)
		switch {
		case got == nil && tt.want == nil:
		case got == nil && tt.want != nil ||
			got != nil && tt.want == nil ||
			got.ID != tt.want.ID:

			c.Errorf("test %s: LookupReservedIdentityByLabels() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
