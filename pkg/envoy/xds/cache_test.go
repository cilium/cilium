// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"

	"github.com/cilium/cilium/pkg/container/set"
)

func versionedResourceNames(resources []VersionedResource) []string {
	names := make([]string, 0, len(resources))
	for _, vr := range resources {
		names = append(names, vr.Name)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	return names
}

func TestGetResourcesSotW(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)
	c.resources[cacheKey{typeURL: "a", resourceName: "a1"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "a", resourceName: "a2"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "b", resourceName: "a1"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "b", resourceName: "b2"}] = cacheValue{lastModifiedVersion: 1}

	for _, tc := range []struct {
		desc            string
		typeURL         string
		version         uint64
		getNames        []string
		wantNames       []string
		wantNilResponse bool
	}{
		{
			desc:      "return resource by name",
			typeURL:   "a",
			getNames:  []string{"a1"},
			wantNames: []string{"a1"},
		},
		{
			desc:      "return all resources for given url",
			typeURL:   "a",
			wantNames: []string{"a1", "a2"},
		},
		{
			desc:      "no resources found for given url",
			typeURL:   "c",
			wantNames: []string{},
		},
		{
			desc:      "no resources found for given name and url",
			typeURL:   "b",
			getNames:  []string{"c1"},
			wantNames: []string{},
		},
		{
			desc:            "resource has no updates",
			typeURL:         "b",
			version:         1,
			getNames:        []string{"b2"},
			wantNilResponse: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := c.GetResources(tc.typeURL, tc.version, tc.getNames)
			gotNilResponse := got == nil
			if gotNilResponse != tc.wantNilResponse {
				t.Fatalf("Returned response mismatch want: gotNilResponse != tc.wantNilResponse  %v != %v", gotNilResponse, tc.wantNilResponse)
			}
			if got == nil {
				return
			}
			names := versionedResourceNames(got.VersionedResources)
			if diff := cmp.Diff(names, tc.wantNames); diff != "" {
				t.Fatalf("returned resources mismatch (-got/+want): %v", diff)
			}
		})
	}
}

func TestGetDeltaResources(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)
	c.version = 5
	c.resources[cacheKey{typeURL: "a", resourceName: "a1"}] = cacheValue{lastModifiedVersion: 2}
	c.resources[cacheKey{typeURL: "a", resourceName: "a2"}] = cacheValue{lastModifiedVersion: 5}
	c.resources[cacheKey{typeURL: "a", resourceName: "a3"}] = cacheValue{lastModifiedVersion: 4}

	for _, tc := range []struct {
		desc               string
		subscriptions      []string
		lastAckedVersion   uint64
		ackedResourceNames []string
		forceResponseNames []string
		forceEmptyResponse bool
		wantNames          []string
		wantRemoved        []string
		wantNilResponse    bool
	}{
		{
			desc:             "empty subscriptions are wildcard",
			subscriptions:    nil,
			lastAckedVersion: 0,
			wantNames:        []string{"a1", "a2", "a3"},
		},
		{
			desc:             "wildcard returns all newer resources",
			subscriptions:    []string{"*"},
			lastAckedVersion: 0,
			wantNames:        []string{"a1", "a2", "a3"},
		},
		{
			desc:             "wildcard with named subscription still behaves as wildcard",
			subscriptions:    []string{"*", "a1"},
			lastAckedVersion: 0,
			wantNames:        []string{"a1", "a2", "a3"},
		},
		{
			desc:               "force response names resend unchanged resources",
			subscriptions:      []string{"a1"},
			lastAckedVersion:   5,
			forceResponseNames: []string{"a1"},
			wantNames:          []string{"a1"},
		},
		{
			desc:               "force response names resend unchanged resources with wildcard",
			subscriptions:      []string{"*"},
			lastAckedVersion:   5,
			forceResponseNames: []string{"a1"},
			wantNames:          []string{"a1"},
		},
		{
			desc:               "removed names only from still tracked acked names",
			subscriptions:      []string{"a1", "a4"},
			lastAckedVersion:   5,
			ackedResourceNames: []string{"a1", "a3", "a4"},
			wantNames:          []string{},
			wantRemoved:        []string{"a4"},
		},
		{
			desc:               "wildcard removals are not filtered by explicit names",
			subscriptions:      []string{"*", "a1"},
			lastAckedVersion:   5,
			ackedResourceNames: []string{"a4"},
			wantNames:          []string{},
			wantRemoved:        []string{"a4"},
		},
		{
			desc:               "unsubscribed names do not produce removals",
			subscriptions:      []string{"a1"},
			lastAckedVersion:   5,
			ackedResourceNames: []string{"a2"},
			wantNilResponse:    true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := c.GetDeltaResources("a", tc.lastAckedVersion, set.NewSet(tc.subscriptions...), set.NewSet(tc.ackedResourceNames...), set.NewSet(tc.forceResponseNames...), tc.forceEmptyResponse)
			if (got == nil) != tc.wantNilResponse {
				t.Fatalf("GetDeltaResources() nil response mismatch: got %v wantNil %v", got == nil, tc.wantNilResponse)
			}
			if got == nil {
				return
			}
			if diff := cmp.Diff(versionedResourceNames(got.VersionedResources), tc.wantNames); diff != "" {
				t.Fatalf("returned resources mismatch (-got/+want): %s", diff)
			}
			if diff := cmp.Diff(got.RemovedNames, tc.wantRemoved); diff != "" {
				t.Fatalf("returned removed names mismatch (-got/+want): %s", diff)
			}
		})
	}
}

func TestCacheVersionStateRotatesOnRealBumps(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)

	version, changed := c.VersionState()
	if version != 1 {
		t.Fatalf("unexpected initial version: got %d want 1", version)
	}

	_, updated, _ := c.Upsert("a", resources[0].Name, resources[0])
	if !updated {
		t.Fatal("expected cache upsert to update version")
	}

	select {
	case <-changed:
	case <-time.After(TestTimeout):
		t.Fatal("timed out waiting for version state channel to close")
	}

	version, nextChanged := c.VersionState()
	if version != 2 {
		t.Fatalf("unexpected bumped version: got %d want 2", version)
	}
	if changed == nextChanged {
		t.Fatal("expected a fresh version channel after version bump")
	}

	c.EnsureVersion("a", 4)
	select {
	case <-nextChanged:
	case <-time.After(TestTimeout):
		t.Fatal("timed out waiting for EnsureVersion to rotate the channel")
	}

	version, _ = c.VersionState()
	if version != 4 {
		t.Fatalf("unexpected version after EnsureVersion: got %d want 4", version)
	}

	got := c.GetResources("a", 0, []string{resources[0].Name})
	if got == nil || len(got.VersionedResources) != 1 {
		t.Fatal("expected resource to remain present after EnsureVersion")
	}
	if got.VersionedResources[0].Version != 4 {
		t.Fatalf("unexpected resource version after EnsureVersion: got %d want 4", got.VersionedResources[0].Version)
	}
}

func TestCacheVersionStateDoesNotRotateOnNoopUpdate(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)

	msg := resources[0]
	_, updated, _ := c.Upsert("a", resources[0].Name, msg)
	if !updated {
		t.Fatal("expected first upsert to update cache")
	}

	version, changed := c.VersionState()
	_, updated, _ = c.Upsert("a", resources[0].Name, msg)
	if updated {
		t.Fatal("expected identical upsert to be a no-op")
	}

	select {
	case <-changed:
		t.Fatal("version state channel unexpectedly rotated on no-op update")
	default:
	}

	versionAfter, changedAfter := c.VersionState()
	if versionAfter != version {
		t.Fatalf("unexpected version change on no-op update: got %d want %d", versionAfter, version)
	}
	if changedAfter != changed {
		t.Fatal("version state channel unexpectedly changed on no-op update")
	}
}
