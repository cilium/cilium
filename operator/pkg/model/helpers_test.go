// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddSource(t *testing.T) {

	testSource := FullyQualifiedResource{
		Name:      "testSource",
		Namespace: "testNamespace",
		Group:     "group",
		Version:   "v1",
		Kind:      "Test",
	}

	emptySlice := []FullyQualifiedResource{}

	existsSlice := []FullyQualifiedResource{testSource}

	nonexistSlice := []FullyQualifiedResource{
		{
			Name: "SomeOtherResource",
		},
	}

	emptyOut := AddSource(emptySlice, testSource)
	assert.Equal(t, existsSlice, emptyOut)

	existsOut := AddSource(existsSlice, testSource)
	assert.Equal(t, existsSlice, existsOut)

	nonexistOut := AddSource(nonexistSlice, testSource)
	assert.Equal(t, append(nonexistSlice, testSource), nonexistOut)

}

func TestComputeHosts(t *testing.T) {
	type args struct {
		routeHostnames   []string
		listenerHostname *string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "no route hostnames, no listener hostname",
			args: args{},
			want: []string{"*"},
		},
		{
			name: "no route hostnames",
			args: args{
				listenerHostname: strp("*.foo.com"),
			},
			want: []string{"*.foo.com"},
		},
		{
			name: "matching specific hostname exactly",
			args: args{
				routeHostnames: []string{
					"non.matching.com",
					"*.nonmatchingwildcard.io",
					"very.specific.com",
				},
				listenerHostname: strp("very.specific.com"),
			},
			want: []string{"very.specific.com"},
		},
		{
			name: "matching specific hostname on wildcard",
			args: args{
				routeHostnames: []string{
					"non.matching.com",
					"*.nonmatchingwildcard.io",
					"*.specific.com",
				},
				listenerHostname: strp("very.specific.com"),
			},
			want: []string{"very.specific.com"},
		},
		{
			name: "matching wildcard hostname",
			args: args{
				routeHostnames: []string{
					"non.matching.com",
					"*.nonmatchingwildcard.io",
					"wildcard.io",
					"foo.wildcard.io",
					"bar.wildcard.io",
					"foo.bar.wildcard.io",
					"very.specific.com",
				},
				listenerHostname: strp("*.wildcard.io"),
			},
			want: []string{"bar.wildcard.io", "foo.bar.wildcard.io", "foo.wildcard.io"},
		},
		{
			name: "matching wildcard hostname exactly",
			args: args{
				routeHostnames: []string{
					"non.matching.com",
					"*.nonmatchingwildcard.io",
					"wildcard.io",
					"*.wildcard.io",
					"very.specific.com",
				},
				listenerHostname: strp("*.wildcard.io"),
			},
			want: []string{"*.wildcard.io"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeHosts(tt.args.routeHostnames, tt.args.listenerHostname)
			assert.Equalf(t, tt.want, got, "ComputeHosts(%v, %v)", tt.args.routeHostnames, tt.args.listenerHostname)
		})
	}
}

func strp(s string) *string {
	return &s
}
