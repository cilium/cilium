// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"testing"

	"github.com/go-openapi/spec"

	"github.com/cilium/cilium/pkg/checker"
)

func TestParseSpecPaths(t *testing.T) {
	testCases := [...]struct {
		name     string
		paths    *spec.Paths
		expected PathSet
	}{
		{
			name: "Basic GET BGP",
			paths: &spec.Paths{Paths: map[string]spec.PathItem{
				"/bgp": {PathItemProps: spec.PathItemProps{
					Get: &spec.Operation{},
				}}}},
			expected: PathSet{
				"GetBGP": {
					Method: "GET",
					Path:   "/bgp",
				}},
		},
		{
			name: "PUT endpoints by ID",
			paths: &spec.Paths{Paths: map[string]spec.PathItem{
				"/endpoint/{id}": {PathItemProps: spec.PathItemProps{
					Put: &spec.Operation{},
				}}}},
			expected: PathSet{
				"PutEndpointID": {
					Method: "PUT",
					Path:   "/endpoint/{id}",
				}},
		},
		{
			name: "DELETE LRP by ID with suffix",
			paths: &spec.Paths{Paths: map[string]spec.PathItem{
				"/lrp/{id}/foo": {PathItemProps: spec.PathItemProps{
					Delete: &spec.Operation{},
				}}}},
			expected: PathSet{
				"DeleteLRPIDFoo": {
					Method: "DELETE",
					Path:   "/lrp/{id}/foo",
				}},
		},
		{
			name: "POST kebab-case",
			paths: &spec.Paths{Paths: map[string]spec.PathItem{
				"/cgroup-metadata-dump": {PathItemProps: spec.PathItemProps{
					Post: &spec.Operation{},
				}}}},
			expected: PathSet{
				"PostCgroupMetadataDump": {
					Method: "POST",
					Path:   "/cgroup-metadata-dump",
				}},
		},
		{
			name: "Multiple endpoints PATCH and PUT",
			paths: &spec.Paths{Paths: map[string]spec.PathItem{
				"/endpoint/{id}": {PathItemProps: spec.PathItemProps{
					Put: &spec.Operation{},
				}},
				"/endpoint/{id}/config": {PathItemProps: spec.PathItemProps{
					Patch: &spec.Operation{},
				}},
			}},
			expected: PathSet{
				"PatchEndpointIDConfig": {
					Method: "PATCH",
					Path:   "/endpoint/{id}/config",
				},
				"PutEndpointID": {
					Method: "PUT",
					Path:   "/endpoint/{id}",
				},
			},
		},
		{
			name: "Multiple methods PATCH and PUT ipam",
			paths: &spec.Paths{Paths: map[string]spec.PathItem{
				"/ipam/{ip}": {PathItemProps: spec.PathItemProps{
					Put:   &spec.Operation{},
					Patch: &spec.Operation{},
				}},
			}},
			expected: PathSet{
				"PatchIPAMIP": {
					Method: "PATCH",
					Path:   "/ipam/{ip}",
				},
				"PutIPAMIP": {
					Method: "PUT",
					Path:   "/ipam/{ip}",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSpecPaths(tc.paths)
			if ok, msg := checker.DeepEqual(got, tc.expected); !ok {
				t.Errorf("case %q failed:\n%s", tc.name, msg)
			}
		})
	}
}

func TestAllowedFlagsToDeniedPaths(t *testing.T) {
	sampleFlags := PathSet{
		"GetEndpoint":           {Method: "GET", Path: "/endpoint"},
		"PutEndpointID":         {Method: "PUT", Path: "/endpoint/{id}"},
		"PatchEndpointIDConfig": {Method: "PATCH", Path: "/endpoint/{id}/config"},
	}
	testCases := [...]struct {
		name        string
		allowed     []string
		expected    PathSet
		expectedErr error
	}{
		{
			name:    "deny all",
			allowed: []string{},
			expected: PathSet{
				"GetEndpoint":           {Method: "GET", Path: "/endpoint"},
				"PutEndpointID":         {Method: "PUT", Path: "/endpoint/{id}"},
				"PatchEndpointIDConfig": {Method: "PATCH", Path: "/endpoint/{id}/config"},
			},
		},
		{
			name:     "wildcard: allow all",
			allowed:  []string{"*"},
			expected: PathSet{},
		},
		{
			name:    "wildcard: allow gets",
			allowed: []string{"Get*"},
			expected: PathSet{
				"PutEndpointID":         {Method: "PUT", Path: "/endpoint/{id}"},
				"PatchEndpointIDConfig": {Method: "PATCH", Path: "/endpoint/{id}/config"},
			},
		},
		{
			name:        "allow invalid option",
			allowed:     []string{"NoSuchOption"},
			expected:    PathSet(nil),
			expectedErr: ErrUnknownFlag,
		},
		{
			name:        "deny all empty string",
			allowed:     []string{""},
			expected:    PathSet(nil),
			expectedErr: ErrUnknownFlag,
		},
		{
			name:        "wildcard: invalid prefix",
			allowed:     []string{"*foo"},
			expected:    PathSet(nil),
			expectedErr: ErrUnknownWildcard,
		},
		{
			name:        "wildcard: invalid multiple wildcard",
			allowed:     []string{"foo*bar*"},
			expected:    PathSet(nil),
			expectedErr: ErrUnknownWildcard,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := generateDeniedAPIEndpoints(sampleFlags, tc.allowed)
			if ok, msg := checker.DeepEqual(got, tc.expected); !ok {
				t.Errorf("case %q failed:\n%s", tc.name, msg)
			}
			if ok, msg := checker.DeepEqual(errors.Unwrap(err), tc.expectedErr); !ok {
				t.Errorf("case %q error mismatch:\n%s", tc.name, msg)
			}
		})
	}

}
