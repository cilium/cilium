// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package watchers

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

const (
	testNamespace = "default"
)

type endpointUpdate struct {
	OldEP, NewEP *types.CiliumEndpoint
}

func repr(e *types.CiliumEndpoint) string {
	if e == nil {
		return "nil"
	}
	return fmt.Sprintf("CiliumEndpoint{Key: %q ID: %d}", fmt.Sprintf("%s/%s", e.Namespace, e.Name), e.Identity.ID)
}

func (u endpointUpdate) String() string {
	return fmt.Sprintf("(%s, %s)", repr(u.OldEP), repr(u.NewEP))
}

func epEqual(e1, e2 *types.CiliumEndpoint) bool {
	return ((e1 == nil) == (e2 == nil)) && (e1 == nil || e1.Identity.ID == e2.Identity.ID)
}

func updateEqual(u1, u2 endpointUpdate) bool {
	return epEqual(u1.OldEP, u2.OldEP) && epEqual(u1.NewEP, u2.NewEP)
}

// endpointLess compares two endpoints for the purposes of sorting.
// Returns true if `b` is "greater".
// This function only considers name and ID, as those are the variables used during tests.
func endpointLess(a, b *types.CiliumEndpoint) bool {
	if a == nil {
		return true
	}
	if b == nil {
		return false
	}
	if b.Name == a.Name {
		return b.Identity.ID > a.Identity.ID
	}
	return b.Name > a.Name
}

// updateLess compares two endpoint updates for the purposes of sorting.
// This is safe because an update always has a new endpoint.
func updateLess(a, b endpointUpdate) bool {
	return endpointLess(a.NewEP, b.NewEP)
}

// fakeEPWatcher is a stub that stores observed events.
type fakeEPWatcher struct {
	updates []endpointUpdate
	deleted []*types.CiliumEndpoint
}

func newFakeEPWatcher() *fakeEPWatcher {
	return &fakeEPWatcher{}
}

func (w *fakeEPWatcher) reset() {
	w.updates = []endpointUpdate(nil)
	w.deleted = []*types.CiliumEndpoint(nil)
}

func (w *fakeEPWatcher) endpointUpdated(oldC, newC *types.CiliumEndpoint) {
	w.updates = append(w.updates, endpointUpdate{oldC, newC})
}

func (w *fakeEPWatcher) endpointDeleted(c *types.CiliumEndpoint) {
	w.deleted = append(w.deleted, c)
}

func (w *fakeEPWatcher) assertUpdate(u endpointUpdate) (string, bool) {
	var latest endpointUpdate
	if len(w.updates) > 0 {
		latest = w.updates[len(w.updates)-1]
	}
	if !updateEqual(latest, u) {
		return fmt.Sprintf("Expected %s, got %s", u, latest), false
	}
	return "", true
}

func (w *fakeEPWatcher) assertNoDelete() (string, bool) {
	if len(w.deleted) > 0 {
		return fmt.Sprintf("Expected no delete, got %v", w.deleted), false
	}
	return "", true
}

func (w *fakeEPWatcher) assertLastDelete(e *types.CiliumEndpoint) (string, bool) {
	var latest *types.CiliumEndpoint
	if len(w.deleted) > 0 {
		latest = w.deleted[len(w.deleted)-1]
	}
	if !epEqual(latest, e) {
		return fmt.Sprintf("Expected no delete, got %s", repr(latest)), false
	}
	return "", true
}

type cacheEntry struct {
	Key   string
	Value *endpoint.Endpoint
}

func newFakeEndpointCache(entries ...cacheEntry) *fakeEndpointCache {
	epByName := map[string]*endpoint.Endpoint{}
	for _, entry := range entries {
		epByName[entry.Key] = entry.Value
	}
	return &fakeEndpointCache{
		epByName: epByName,
	}
}

type fakeEndpointCache struct {
	epByName map[string]*endpoint.Endpoint
}

func (c *fakeEndpointCache) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	// Current usage only necessitates returning non-nil object.
	if _, ok := c.epByName[namespacedName]; ok {
		return &endpoint.Endpoint{}
	}
	return nil
}

func newCES(name, namespace string, endpoints ...v2alpha1.CoreCiliumEndpoint) *v2alpha1.CiliumEndpointSlice {
	return &v2alpha1.CiliumEndpointSlice{
		Namespace: namespace,
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
		Endpoints: endpoints,
	}
}

func newEndpoint(name, namespace string, id int64) *types.CiliumEndpoint {
	return &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Identity:   &v2.EndpointIdentity{ID: id},
		Encryption: &v2.EncryptionSpec{},
	}
}

// TestCESSubscriber_CEPTransfer tests a CEP being transferred between two
// CESes. The order of events:
// 1. CES add event for the new CES with latest CEP state
// 2. CES add event for the old CES with old CEP state
// 3. CES delete event for the old CES.
func TestCESSubscriber_CEPTransferOnStartup(t *testing.T) {
	cepNamespace := "ns1"
	cepName := "cep1"
	newCEPID := int64(3)
	oldCEPID := int64(2)
	fakeEPWatcher := newFakeEPWatcher()
	fakeEndpointCache := &fakeEndpointCache{}
	cesSub := &cesSubscriber{
		epWatcher: fakeEPWatcher,
		epCache:   fakeEndpointCache,
		cepMap:    newCEPToCESMap(),
	}
	// Add for new CES
	cesSub.OnAdd(
		newCES("new-ces", cepNamespace,
			v2alpha1.CoreCiliumEndpoint{
				Name:       cepName,
				IdentityID: newCEPID,
			},
		))
	diff, ok := fakeEPWatcher.assertUpdate(endpointUpdate{
		NewEP: newEndpoint("cep1", "ns1", newCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	// Add for old CES
	cesSub.OnAdd(
		newCES("old-ces", cepNamespace,
			v2alpha1.CoreCiliumEndpoint{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		))
	diff, ok = fakeEPWatcher.assertUpdate(endpointUpdate{
		OldEP: newEndpoint("cep1", "ns1", newCEPID),
		NewEP: newEndpoint("cep1", "ns1", oldCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	// Delete the old CES
	cesSub.OnDelete(
		newCES("old-ces", cepNamespace,
			v2alpha1.CoreCiliumEndpoint{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		))
	diff, ok = fakeEPWatcher.assertUpdate(endpointUpdate{
		OldEP: newEndpoint("cep1", "ns1", oldCEPID),
		NewEP: newEndpoint("cep1", "ns1", newCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	diff, ok = fakeEPWatcher.assertNoDelete()
	if !ok {
		t.Fatal(diff)
	}
	wantCEPMap := map[string]cesToCEPRef{
		"ns1/cep1": {
			"new-ces": newEndpoint("cep1", "ns1", 3),
		},
	}
	if diff := cmp.Diff(wantCEPMap, cesSub.cepMap.cepMap); diff != "" {
		t.Fatalf("Unexpected CEP map (-want +got):\n%s", diff)
	}
}

// TestCESSubscriber_CEPTransferViaUpdate tests a CEP being transferred between
// two CESes. The order of events:
// 1. CES add event for the old CES with old CEP state
// 2. CES update event for the old CES with deleting old CEP state
// 3. CES update event for the new CES with latest CEP state
func TestCESSubscriber_CEPTransferViaUpdate(t *testing.T) {
	cepNamespace := "ns1"
	cepName := "cep1"
	newCEPID := int64(3)
	oldCEPID := int64(2)
	fakeEPWatcher := newFakeEPWatcher()
	fakeEndpointCache := &fakeEndpointCache{}
	cesSub := &cesSubscriber{
		epWatcher: fakeEPWatcher,
		epCache:   fakeEndpointCache,
		cepMap:    newCEPToCESMap(),
	}
	// Add for old CES
	cesSub.OnAdd(
		newCES("old-ces", cepNamespace,
			v2alpha1.CoreCiliumEndpoint{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		))
	diff, ok := fakeEPWatcher.assertUpdate(endpointUpdate{
		NewEP: newEndpoint("cep1", "ns1", oldCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	// Update for old CES removing CEP
	cesSub.OnUpdate(
		newCES("old-ces", cepNamespace,
			v2alpha1.CoreCiliumEndpoint{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		),
		newCES("old-ces", cepNamespace))

	diff, ok = fakeEPWatcher.assertLastDelete(newEndpoint("cep1", "ns1", oldCEPID))
	if !ok {
		t.Fatal(diff)
	}
	// Update for new CES
	cesSub.OnUpdate(
		newCES("new-ces", cepNamespace),
		newCES("new-ces", cepNamespace,
			v2alpha1.CoreCiliumEndpoint{
				Name:       cepName,
				IdentityID: newCEPID,
			},
		))
	diff, ok = fakeEPWatcher.assertUpdate(endpointUpdate{
		NewEP: newEndpoint("cep1", "ns1", newCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	wantCEPMap := map[string]cesToCEPRef{
		"ns1/cep1": {
			"new-ces": newEndpoint("cep1", "ns1", 3),
		},
	}
	if diff := cmp.Diff(wantCEPMap, cesSub.cepMap.cepMap); diff != "" {
		t.Fatalf("Unexpected CEP map (-want +got):\n%s", diff)
	}
}

func TestCESSubscriber_deleteCEPfromCES(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		initCEPMap     map[string]cesToCEPRef
		initCurrentCES map[string]string
		deletedCesName string
		deletedCep     *types.CiliumEndpoint
		expectedUpdate endpointUpdate
		expectedDelete *types.CiliumEndpoint
	}{
		{
			desc: "delete CEP triggers deletion",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"ces1": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "ces1"},
			deletedCesName: "ces1",
			deletedCep:     newEndpoint("cep1", "ns1", 3),
			expectedDelete: newEndpoint("cep1", "ns1", 3),
		},
		{
			desc: "delete CEP triggers update",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"ces1": newEndpoint("cep1", "ns1", 2),
					"ces2": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "ces1"},
			deletedCesName: "ces1",
			deletedCep:     newEndpoint("cep1", "ns1", 2),
			expectedUpdate: endpointUpdate{
				OldEP: newEndpoint("cep1", "ns1", 2),
				NewEP: newEndpoint("cep1", "ns1", 3),
			},
		},
		{
			desc: "delete CEP triggers no update or deletion",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"ces1": newEndpoint("cep1", "ns1", 1),
					"ces2": newEndpoint("cep1", "ns1", 2),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "ces1"},
			deletedCesName: "ces2",
			deletedCep:     newEndpoint("cep1", "ns1", 2),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			fakeEPWatcher := newFakeEPWatcher()
			cesSub := &cesSubscriber{
				epWatcher: fakeEPWatcher,
				cepMap:    newCEPToCESMap(),
			}
			if tc.initCEPMap != nil {
				cesSub.cepMap.cepMap = tc.initCEPMap
			}
			if tc.initCurrentCES != nil {
				cesSub.cepMap.currentCES = tc.initCurrentCES
			}
			cepName := tc.deletedCep.Namespace + "/" + tc.deletedCep.Name
			cesSub.deleteCEPfromCES(cepName, tc.deletedCesName, tc.deletedCep)
			diff, ok := fakeEPWatcher.assertUpdate(tc.expectedUpdate)
			if !ok {
				t.Error(diff)
			}
			diff, ok = fakeEPWatcher.assertLastDelete(tc.expectedDelete)
			if !ok {
				t.Error(diff)
			}
		})
	}
}

func TestCEPToCESmap_insertCEP(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		initCEPMap     map[string]cesToCEPRef
		initCurrentCES map[string]string
		cesName        string
		cep            *types.CiliumEndpoint
		wantCEPMap     map[string]cesToCEPRef
		wantCurrentCES map[string]string
	}{
		{
			desc:    "add new cep",
			cep:     newEndpoint("cep1", "ns1", 3),
			cesName: "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "update cep object",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cep:            newEndpoint("cep1", "ns1", 1),
			cesName:        "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 1),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "add new ces for existing cep",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cep:            newEndpoint("cep1", "ns1", 1),
			cesName:        "cesy",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
					"cesy": newEndpoint("cep1", "ns1", 1),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesy"},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cepToCESmap := newCEPToCESMap()
			if tc.initCEPMap != nil {
				cepToCESmap.cepMap = tc.initCEPMap
			}
			if tc.initCurrentCES != nil {
				cepToCESmap.currentCES = tc.initCurrentCES
			}
			cepName := tc.cep.Namespace + "/" + tc.cep.Name
			cepToCESmap.insertCEPLocked(cepName, tc.cesName, tc.cep)
			if diff := cmp.Diff(tc.wantCEPMap, cepToCESmap.cepMap); diff != "" {
				t.Fatalf("Unexpected CEP map entries (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantCurrentCES, cepToCESmap.currentCES); diff != "" {
				t.Fatalf("Unexpected currentCES map entries (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCEPToCESmap_deleteCEP(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		initCEPMap     map[string]cesToCEPRef
		initCurrentCES map[string]string
		cesName        string
		cepName        string
		wantCEPMap     map[string]cesToCEPRef
		wantCurrentCES map[string]string
	}{
		{
			desc: "missing ces does not delete any entries",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep1",
			cesName:        "cesy",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "missing cep does not delete any entries",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep2",
			cesName:        "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "last ces entry",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep1",
			cesName:        "cesx",
			wantCEPMap:     map[string]cesToCEPRef{},
			wantCurrentCES: map[string]string{},
		},
		{
			desc: "multiple ces entries",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": newEndpoint("cep1", "ns1", 3),
					"cesy": newEndpoint("cep1", "ns1", 2),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep1",
			cesName:        "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesy": newEndpoint("cep1", "ns1", 2),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesy"},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cepToCESmap := newCEPToCESMap()
			if tc.initCEPMap != nil {
				cepToCESmap.cepMap = tc.initCEPMap
			}
			if tc.initCurrentCES != nil {
				cepToCESmap.currentCES = tc.initCurrentCES
			}
			cepToCESmap.deleteCEPLocked(tc.cepName, tc.cesName)
			if diff := cmp.Diff(tc.wantCEPMap, cepToCESmap.cepMap); diff != "" {
				t.Fatalf("Unexpected CEP map entries (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantCurrentCES, cepToCESmap.currentCES); diff != "" {
				t.Fatalf("Unexpected currentCES map entries (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCESSubscriber_OnAdd(t *testing.T) {
	testCases := []struct {
		name       string
		local      []cacheEntry
		ces        *v2alpha1.CiliumEndpointSlice
		expectAdds []endpointUpdate
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "one_cep",
			ces:  newCES("ces", testNamespace, v2alpha1.CoreCiliumEndpoint{Name: "cep1"}),
			expectAdds: []endpointUpdate{
				{NewEP: newEndpoint("cep1", testNamespace, 0)},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
			},
		},
		{
			name: "two_ceps",
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			expectAdds: []endpointUpdate{
				{NewEP: newEndpoint("cep1", testNamespace, 0)},
				{NewEP: newEndpoint("cep2", testNamespace, 0)},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "add_local",
			local: []cacheEntry{
				{Key: "default/cep1"},
			},
			ces: newCES("ces", testNamespace, v2alpha1.CoreCiliumEndpoint{Name: "cep1"}),
			expectAdds: []endpointUpdate{
				{NewEP: newEndpoint("cep1", testNamespace, 0)},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := newFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   newFakeEndpointCache(tc.local...),
				cepMap:    m,
			}

			subscriber.OnAdd(tc.ces)

			if diff := cmp.Diff(tc.expectAdds, watcher.updates, cmpopts.SortSlices(updateLess)); diff != "" {
				t.Errorf("Unexpected CEP updates(s) (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tc.expectedCurrentCES, m.currentCES); diff != "" {
				t.Fatalf("Unexpected CEP to CES mapping (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCESSubscriber_OnUpdate(t *testing.T) {
	testCases := []struct {
		name           string
		local          []cacheEntry
		newCES, oldCES *v2alpha1.CiliumEndpointSlice
		expectUpdates  []endpointUpdate
		expectDeleted  []*types.CiliumEndpoint
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "update_all",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep1",
					IdentityID: 1,
				},
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep2",
					IdentityID: 1,
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep1",
					IdentityID: 2,
				},
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep2",
					IdentityID: 2,
				},
			),
			expectUpdates: []endpointUpdate{
				{
					OldEP: newEndpoint("cep1", testNamespace, 1),
					NewEP: newEndpoint("cep1", testNamespace, 2),
				},
				{
					OldEP: newEndpoint("cep2", testNamespace, 1),
					NewEP: newEndpoint("cep2", testNamespace, 2),
				},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "update_cep1",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep1",
					IdentityID: 1,
				},
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep2",
					IdentityID: 1,
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep1",
					IdentityID: 2,
				},
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep2",
					IdentityID: 1,
				},
			),
			expectUpdates: []endpointUpdate{
				{
					OldEP: newEndpoint("cep1", testNamespace, 1),
					NewEP: newEndpoint("cep1", testNamespace, 2),
				},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "no_changes",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "add_cep2",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			expectUpdates: []endpointUpdate{
				{NewEP: newEndpoint("cep2", testNamespace, 0)},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "delete_cep2",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
			),
			expectDeleted: []*types.CiliumEndpoint{
				newEndpoint("cep2", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
			},
		},
		{
			name: "add_update_delete",
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep1",
					IdentityID: 1,
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep2",
				},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{
					Name:       "cep1",
					IdentityID: 2,
				},
				v2alpha1.CoreCiliumEndpoint{
					Name: "cep3",
				},
			),
			expectUpdates: []endpointUpdate{
				{
					NewEP: newEndpoint("cep3", testNamespace, 0),
				},
				{
					OldEP: newEndpoint("cep1", testNamespace, 1),
					NewEP: newEndpoint("cep1", testNamespace, 2),
				},
			},
			expectDeleted: []*types.CiliumEndpoint{
				newEndpoint("cep2", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep3": "ces",
			},
		},
		{
			name: "keep_local_cep2",
			local: []cacheEntry{
				{Key: "default/cep2"},
			},
			oldCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			newCES: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
			),
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := newFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   newFakeEndpointCache(tc.local...),
				cepMap:    m,
			}
			// Initialize state, but do not record the events.
			subscriber.OnAdd(tc.oldCES)
			watcher.reset()

			subscriber.OnUpdate(tc.oldCES, tc.newCES)

			if diff := cmp.Diff(tc.expectUpdates, watcher.updates, cmpopts.SortSlices(updateLess)); diff != "" {
				t.Errorf("Unexpected CEP updates(s) (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectDeleted, watcher.deleted); diff != "" {
				t.Errorf("Unexpected CEP deletion(s) (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectedCurrentCES, m.currentCES); diff != "" {
				t.Fatalf("Unexpected CEP to CES mapping (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCESSubscriber_OnDelete(t *testing.T) {
	testCases := []struct {
		name          string
		local         []cacheEntry
		ces           *v2alpha1.CiliumEndpointSlice
		expectDeleted []*types.CiliumEndpoint
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "one_cep",
			ces:  newCES("ces", testNamespace, v2alpha1.CoreCiliumEndpoint{Name: "cep1"}),
			expectDeleted: []*types.CiliumEndpoint{
				newEndpoint("cep1", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{},
		},
		{
			name: "two_ceps",
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			expectDeleted: []*types.CiliumEndpoint{
				newEndpoint("cep1", testNamespace, 0),
				newEndpoint("cep2", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{},
		},
		{
			name: "keep_cep1",
			local: []cacheEntry{
				{Key: "default/cep1"},
			},
			ces: newCES("ces", testNamespace,
				v2alpha1.CoreCiliumEndpoint{Name: "cep1"},
				v2alpha1.CoreCiliumEndpoint{Name: "cep2"},
			),
			expectDeleted: []*types.CiliumEndpoint{
				newEndpoint("cep2", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := newFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   newFakeEndpointCache(tc.local...),
				cepMap:    m,
			}
			// Initialize state, but do not record the events.
			subscriber.OnAdd(tc.ces)
			watcher.reset()

			subscriber.OnDelete(tc.ces)

			if diff := cmp.Diff(tc.expectDeleted, watcher.deleted); diff != "" {
				t.Errorf("Unexpected CEP deletion(s) (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectedCurrentCES, m.currentCES); diff != "" {
				t.Fatalf("Unexpected CEP to CES mapping (-want +got):\n%s", diff)
			}
		})
	}
}
