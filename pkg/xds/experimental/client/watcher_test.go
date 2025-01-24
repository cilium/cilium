// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package xdsclient

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

type fakeObservableResources struct {
	OnAdd          func(xds.ResourceVersionObserver)
	OnRemove       func(xds.ResourceVersionObserver)
	OnGetResources func(string, uint64, []string) (*xds.VersionedResources, error)
}

func (f *fakeObservableResources) AddResourceVersionObserver(l xds.ResourceVersionObserver) {
	f.OnAdd(l)
}

func (f *fakeObservableResources) RemoveResourceVersionObserver(l xds.ResourceVersionObserver) {
	f.OnRemove(l)
}

func (f *fakeObservableResources) GetResources(typeUrl string, latestVersion uint64, _ string, resourceNames []string) (*xds.VersionedResources, error) {
	return f.OnGetResources(typeUrl, latestVersion, resourceNames)
}

func (f *fakeObservableResources) EnsureVersion(typeUrl string, version uint64) {}

var _ xds.ObservableResourceSource = (*fakeObservableResources)(nil)

func TestWatcher_AddRemove(t *testing.T) {
	var registeredObserver xds.ResourceVersionObserver
	fObsRes := &fakeObservableResources{
		OnAdd: func(rvo xds.ResourceVersionObserver) { registeredObserver = rvo },
		OnRemove: func(rvo xds.ResourceVersionObserver) {
			if rvo != registeredObserver {
				t.Errorf("tried deregistering a different handler, got = %+v, want = %+v", rvo, registeredObserver)
			}
			registeredObserver = nil
		},
	}
	w := newCallbackManager(slog.Default(), fObsRes)

	typeUrl := "test-url"
	cb := func(res *xds.VersionedResources) {}
	id := w.Add(typeUrl, cb)
	if registeredObserver == nil {
		t.Error("expected callback to be registered")
	}

	w.Remove(123) // should do nothing (doesn't exist)
	if registeredObserver == nil {
		t.Error("expected callback to be registered")
	}

	w.Remove(id) // remove
	if registeredObserver != nil {
		t.Error("expected callback to not be registered")
	}

	w.Remove(id) // should do nothing (double removal)
	if registeredObserver != nil {
		t.Error("expected callback to not be registered")
	}

	id2 := w.Add(typeUrl, cb)
	if id2 == id {
		t.Errorf("expected a new ID to be allocated, got = %d, prevId = %d", id2, id)
	}
	w.Remove(id2)
}

func TestWatcher_ResourceCallback(t *testing.T) {
	const testTypeUrl = "test-type-url"

	testCases := []struct {
		name    string
		typeUrl string
		want    *xds.VersionedResources
		called  bool
		err     error
	}{
		{
			name:    "ok",
			typeUrl: testTypeUrl,
			called:  true,
		},
		{
			name:    "wrong_type_url",
			typeUrl: "different-url",
			called:  false,
		},
		{
			name:    "ignore_err",
			typeUrl: testTypeUrl,
			called:  false,
			err:     fmt.Errorf("test err"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var registeredObserver xds.ResourceVersionObserver
			getResources := make(chan any)
			defer close(getResources)
			fObsRes := &fakeObservableResources{
				OnAdd: func(rvo xds.ResourceVersionObserver) { registeredObserver = rvo },
				OnRemove: func(rvo xds.ResourceVersionObserver) {
					if rvo != registeredObserver {
						t.Errorf("tried deregistering a different handler, got = %+v, want = %+v", rvo, registeredObserver)
					}
					registeredObserver = nil
				},
				OnGetResources: func(_ string, _ uint64, _ []string) (*xds.VersionedResources, error) {
					getResources <- nil
					return tc.want, tc.err
				},
			}

			w := newCallbackManager(slog.Default(), fObsRes)

			cbCh := make(chan *xds.VersionedResources)
			defer close(cbCh)
			cb := func(res *xds.VersionedResources) {
				cbCh <- res
			}

			id := w.Add(testTypeUrl, cb)

			w.watchers[id].HandleNewResourceVersion(tc.typeUrl, 0)
			if tc.called || tc.err != nil {
				<-getResources
			}
			w.Remove(id)

			if tc.called {
				got := <-cbCh
				if got != tc.want {
					t.Errorf("versioned resource changed, got = %+v, want = %+v", got, tc.want)
				}
			} else if len(getResources) != 0 || len(cbCh) != 0 {
				t.Error("unexpected callback")
			}
		})
	}

}
