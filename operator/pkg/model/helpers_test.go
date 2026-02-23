// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"slices"
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
		routeHostnames           []string
		listenerHostname         *string
		excludeListenerHostnames []string
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
			want: []string{"foo.bar.wildcard.io", "bar.wildcard.io", "foo.wildcard.io"},
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
		{
			name: "with excluded listener hostname",
			args: args{
				routeHostnames: []string{
					"non.matching.com",
					"*.nonmatchingwildcard.io",
					"wildcard.io",
					"*.wildcard.io",
					"very.specific.com",
				},
				listenerHostname: strp("*"),
				excludeListenerHostnames: []string{
					"non.matching.com",
					"*.nonmatchingwildcard.io",
					"*.wildcard.io",
					"very.specific.com",
				},
			},
			want: []string{"wildcard.io"},
		},
		{
			name: "matching wildcards, listener longer",
			args: args{
				routeHostnames: []string{
					"*.com",
				},
				listenerHostname: strp("*.example.com"),
			},
			want: []string{"*.example.com"},
		},
		{
			name: "matching wildcards, route longer",
			args: args{
				routeHostnames: []string{
					"*.example.com",
				},
				listenerHostname: strp("*.com"),
			},
			want: []string{"*.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeHosts(tt.args.routeHostnames, tt.args.listenerHostname, tt.args.excludeListenerHostnames)
			assert.Equalf(t, tt.want, got, "ComputeHosts(%v, %v)", tt.args.routeHostnames, tt.args.listenerHostname)
		})
	}
}

func strp(s string) *string {
	return &s
}

func Test_wildcardHostnamesIntersect(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		routeHostname    string
		listenerHostname string
		want             bool
	}{
		{
			name:             "wildcard only",
			routeHostname:    "*",
			listenerHostname: "*",
			want:             true,
		},
		{
			name:             "malformed wildcard",
			routeHostname:    "*.",
			listenerHostname: "*.",
			want:             false,
		},
		{
			name:             "longer wildcard listener",
			routeHostname:    "*",
			listenerHostname: "*.com,",
			want:             true,
		},
		{
			name:             "longer wildcard route",
			routeHostname:    "*.com",
			listenerHostname: "*",
			want:             true,
		},
		{
			name:             "two labels listener, one route, matching",
			routeHostname:    "*.com",
			listenerHostname: "*.example.com",
			want:             true,
		},
		{
			name:             "one label listener, two route, matching",
			routeHostname:    "*.example.com",
			listenerHostname: "*.com",
			want:             true,
		},
		{
			name:             "two labels each, matching",
			routeHostname:    "*.example.com",
			listenerHostname: "*.example.com",
			want:             true,
		},
		{
			name:             "one label each, not matching",
			routeHostname:    "*.com",
			listenerHostname: "*.gov",
			want:             false,
		},
		{
			name:             "two labels each, not matching on rightmost",
			routeHostname:    "*.example.com",
			listenerHostname: "*.example.gov",
			want:             false,
		},
		{
			name:             "two labels each, not matching on inner",
			routeHostname:    "*.example.com",
			listenerHostname: "*.other.com",
			want:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wildcardHostnamesIntersect(tt.routeHostname, tt.listenerHostname)
			if got != tt.want {
				t.Errorf("wildcardHostnamesIntersect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_sortHostnamesByWildcards(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		unsorted []string
		sorted   []string
	}{
		{
			name:     "both global wildcard",
			unsorted: []string{"*", "*"},
			sorted:   []string{"*", "*"},
		},
		{
			name:     "a global wildcard",
			unsorted: []string{"*", "com"},
			sorted:   []string{"com", "*"},
		},
		{
			name:     "b global wildcard",
			unsorted: []string{"com", "*"},
			sorted:   []string{"com", "*"},
		},
		{
			name:     "no wildcard, a more labels",
			unsorted: []string{"www.example.com", "example.com"},
			sorted:   []string{"www.example.com", "example.com"},
		},
		{
			name:     "no wildcard, b more labels",
			unsorted: []string{"example.com", "www.example.com"},
			sorted:   []string{"www.example.com", "example.com"},
		},
		{
			name:     "no wildcard, a first lexically",
			unsorted: []string{"foo.example.com", "www.example.com"},
			sorted:   []string{"foo.example.com", "www.example.com"},
		},
		{
			name:     "no wildcard, b first lexically",
			unsorted: []string{"www.example.com", "foo.example.com"},
			sorted:   []string{"foo.example.com", "www.example.com"},
		},
		{
			name:     "b no wildcard, more specific",
			unsorted: []string{"*.example.com", "www.example.com"},
			sorted:   []string{"www.example.com", "*.example.com"},
		},
		{
			name:     "a no wildcard, more specific",
			unsorted: []string{"www.example.com", "*.example.com"},
			sorted:   []string{"www.example.com", "*.example.com"},
		},
		{
			name:     "both wildcards, a more specific",
			unsorted: []string{"*.example.com", "*.com"},
			sorted:   []string{"*.example.com", "*.com"},
		},
		{
			name:     "both wildcards, b more specific",
			unsorted: []string{"*.com", "*.example.com"},
			sorted:   []string{"*.example.com", "*.com"},
		},
		{
			name:     "wildcard with same suffix is less specific",
			unsorted: []string{"*.example.com", "example.com"},
			sorted:   []string{"example.com", "*.example.com"},
		},
		{
			name:     "wildcard with same suffix is less specific, opposite order",
			unsorted: []string{"example.com", "*.example.com"},
			sorted:   []string{"example.com", "*.example.com"},
		},
		{
			name:     "multiple subdomains more specific",
			unsorted: []string{"sub.domain.example.com", "*.example.com"},
			sorted:   []string{"sub.domain.example.com", "*.example.com"},
		},
		{
			name:     "multiple subdomains more specific, opposite order",
			unsorted: []string{"*.example.com", "sub.domain.example.com"},
			sorted:   []string{"sub.domain.example.com", "*.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.unsorted
			slices.SortStableFunc(got, sortHostnamesByWildcards)
			if !slices.Equal(got, tt.sorted) {
				t.Errorf("sortHostnamesByWildcards() want %s, got %s", tt.sorted, got)
			}
		})
	}
}
