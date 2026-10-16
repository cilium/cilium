// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
)

type fakeResourceSource struct {
	mu lock.Mutex

	version uint64
	changed chan struct{}

	getResources func(string, uint64, []string) *xds.VersionedResources
}

func newFakeResourceSource() *fakeResourceSource {
	f := &fakeResourceSource{
		version: 1,
		changed: make(chan struct{}),
	}
	f.getResources = func(typeURL string, latestVersion uint64, resourceNames []string) *xds.VersionedResources {
		return &xds.VersionedResources{Version: f.currentVersion()}
	}
	return f
}

func (f *fakeResourceSource) GetResources(typeURL string, latestVersion uint64, resourceNames []string) *xds.VersionedResources {
	return f.getResources(typeURL, latestVersion, resourceNames)
}

func (f *fakeResourceSource) EnsureVersion(string, uint64) {}

func (f *fakeResourceSource) VersionState() (uint64, <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version, f.changed
}

func (f *fakeResourceSource) bump(version uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.changed
	f.version = version
	f.changed = make(chan struct{})
	close(old)
}

func (f *fakeResourceSource) currentVersion() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version
}

var _ xds.ResourceSource = (*fakeResourceSource)(nil)

func TestWatcher_AddRemove(t *testing.T) {
	src := newFakeResourceSource()
	w := newCallbackManager(slog.Default(), src)

	typeURL := "test-url"
	cb := func(res *xds.VersionedResources) {}
	id := w.Add(typeURL, cb)
	if _, ok := w.watchers[id]; !ok {
		t.Fatal("expected callback to be registered")
	}

	w.Remove(123) // should do nothing (doesn't exist)
	if _, ok := w.watchers[id]; !ok {
		t.Fatal("expected callback to remain registered")
	}

	w.Remove(id)
	if _, ok := w.watchers[id]; ok {
		t.Fatal("expected callback to be removed")
	}

	w.Remove(id) // should do nothing (double removal)
	if len(w.watchers) != 0 {
		t.Fatal("expected watcher set to stay empty after double removal")
	}

	id2 := w.Add(typeURL, cb)
	if id2 == id {
		t.Fatalf("expected a new ID to be allocated, got %d and previous %d", id2, id)
	}
	w.Remove(id2)
}

func TestWatcher_ResourceCallback(t *testing.T) {
	const testTypeURL = "test-type-url"

	type getCall struct {
		typeURL       string
		latestVersion uint64
		resourceNames []string
	}

	getResources := make(chan getCall, 1)
	cbCh := make(chan *xds.VersionedResources, 2)
	src := newFakeResourceSource()
	want := &xds.VersionedResources{Version: 2}
	src.getResources = func(typeURL string, latestVersion uint64, resourceNames []string) *xds.VersionedResources {
		getResources <- getCall{
			typeURL:       typeURL,
			latestVersion: latestVersion,
			resourceNames: resourceNames,
		}
		return want
	}

	w := newCallbackManager(slog.Default(), src)
	id := w.Add(testTypeURL, func(res *xds.VersionedResources) {
		cbCh <- res
	})
	defer w.Remove(id)

	select {
	case <-cbCh:
		t.Fatal("watcher unexpectedly invoked callback immediately on registration")
	case <-time.After(50 * time.Millisecond):
	}

	src.bump(2)

	select {
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for GetResources")
	case call := <-getResources:
		if call.typeURL != testTypeURL {
			t.Fatalf("unexpected type url in GetResources: got %q want %q", call.typeURL, testTypeURL)
		}
		if call.latestVersion != 0 {
			t.Fatalf("unexpected latest version in GetResources: got %d want 0", call.latestVersion)
		}
		if call.resourceNames != nil {
			t.Fatalf("unexpected resource names in GetResources: got %#v want nil", call.resourceNames)
		}
	}

	select {
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback")
	case got := <-cbCh:
		if got != want {
			t.Fatalf("unexpected callback resource: got %+v want %+v", got, want)
		}
	}

	w.Remove(id)
	src.bump(3)
	select {
	case got := <-cbCh:
		t.Fatalf("unexpected callback after removal: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestWatcher_CoalescesRapidVersionBumps(t *testing.T) {
	const testTypeURL = "test-type-url"

	src := newFakeResourceSource()
	callbackStarted := make(chan struct{}, 2)
	releaseCallback := make(chan struct{})
	callbackCount := 0
	src.getResources = func(typeURL string, latestVersion uint64, resourceNames []string) *xds.VersionedResources {
		return &xds.VersionedResources{Version: src.currentVersion()}
	}

	w := newCallbackManager(slog.Default(), src)
	id := w.Add(testTypeURL, func(res *xds.VersionedResources) {
		callbackCount++
		callbackStarted <- struct{}{}
		if callbackCount == 1 {
			<-releaseCallback
		}
	})
	defer w.Remove(id)

	src.bump(2)
	select {
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first callback")
	case <-callbackStarted:
	}

	src.bump(3)
	src.bump(4)
	close(releaseCallback)

	select {
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coalesced callback")
	case <-callbackStarted:
	}

	select {
	case <-callbackStarted:
		t.Fatal("unexpected extra callback after coalesced version bumps")
	case <-time.After(50 * time.Millisecond):
	}
}
