// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/kvstore"
)

func Test_getOldestLeases(t *testing.T) {
	type args struct {
		m map[string]kvstore.Value
	}
	tests := []struct {
		name string
		args args
		want map[string]kvstore.Value
	}{
		{
			name: "test-1",
			args: args{
				m: map[string]kvstore.Value{},
			},
			want: map[string]kvstore.Value{},
		},
		{
			name: "test-2",
			args: args{
				m: map[string]kvstore.Value{
					"foo/bar/1": {
						Data:        nil,
						ModRevision: 1,
						LeaseID:     1,
					},
					"foo/bar/2": {
						Data:        nil,
						ModRevision: 2,
						LeaseID:     2,
					},
					"foo/bar/3": {
						Data:        nil,
						ModRevision: 3,
						LeaseID:     3,
					},
					"foo/bar/4": {
						Data:        nil,
						ModRevision: 4,
						LeaseID:     4,
					},
					"foo/bar/5": {
						Data:        nil,
						ModRevision: 5,
						LeaseID:     5,
					},
					"foo/baz/6": {
						Data:        nil,
						ModRevision: 6,
						LeaseID:     6,
					},
					"foo/bbz/7": {
						Data:        nil,
						ModRevision: 3,
						LeaseID:     3,
					},
				},
			},
			want: map[string]kvstore.Value{
				"foo/bar/1": {
					Data:        nil,
					ModRevision: 1,
					LeaseID:     1,
				},
				"foo/baz/6": {
					Data:        nil,
					ModRevision: 6,
					LeaseID:     6,
				},
				"foo/bbz/7": {
					Data:        nil,
					ModRevision: 3,
					LeaseID:     3,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getOldestLeases(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getOldestLeases() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPath(t *testing.T) {
	type args struct {
		k string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test-1",
			args: args{
				k: "cilium/state/identities/v1/locks/" +
					"k8s:io.cilium.k8s.policy.cluster=default;" +
					"k8s:io.cilium.k8s.policy.serviceaccount=default;" +
					"k8s:io.kubernetes.pod.namespace=default;k8s:k8s-app.guestbook=redis;" +
					"k8s:role=master;" +
					"/29c66fd840fa06f7",
			},
			want: "cilium/state/identities/v1/locks/" +
				"k8s:io.cilium.k8s.policy.cluster=default;" +
				"k8s:io.cilium.k8s.policy.serviceaccount=default;" +
				"k8s:io.kubernetes.pod.namespace=default;k8s:k8s-app.guestbook=redis;" +
				"k8s:role=master;",
		},
		{
			name: "test-2",
			args: args{
				k: "cilium/state/identities/v1/locks/" +
					"k8s:io.cilium.k8s.policy.cluster=default;" +
					"k8s:role=master/////;" +
					"/29c66fd840fa06f7",
			},
			want: "cilium/state/identities/v1/locks/" +
				"k8s:io.cilium.k8s.policy.cluster=default;" +
				"k8s:role=master/////;",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyPathFromLockPath(tt.args.k); got != tt.want {
				t.Errorf("keyPathFromLockPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
