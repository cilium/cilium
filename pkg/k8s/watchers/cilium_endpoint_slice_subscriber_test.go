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

func epToString(e *types.CiliumEndpoint) string {
	if e == nil {
		return "nil"
	}
	return fmt.Sprintf("ep(id: %d)", e.Identity.ID)
}

func (u endpointUpdate) String() string {
	return fmt.Sprintf("(%s, %s)", epToString(u.OldEP), epToString(u.NewEP))
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

type fakeEPWatcher struct {
	updates []endpointUpdate
	deleted []*types.CiliumEndpoint
}

func createFakeEPWatcher() *fakeEPWatcher {
	return &fakeEPWatcher{}
}

func (fw *fakeEPWatcher) reset() {
	fw.updates = []endpointUpdate(nil)
	fw.deleted = []*types.CiliumEndpoint(nil)
}

func (fw *fakeEPWatcher) endpointUpdated(oldC, newC *types.CiliumEndpoint) {
	fw.updates = append(fw.updates, endpointUpdate{oldC, newC})
}

func (fw *fakeEPWatcher) endpointDeleted(c *types.CiliumEndpoint) {
	fw.deleted = append(fw.deleted, c)
}

func (fw *fakeEPWatcher) assertUpdate(u endpointUpdate) (string, bool) {
	var latest endpointUpdate
	if len(fw.updates) > 0 {
		latest = fw.updates[len(fw.updates)-1]
	}
	if !updateEqual(latest, u) {
		return fmt.Sprintf("Expected %s, got %s", u, latest), false
	}
	return "", true
}

func (fw *fakeEPWatcher) assertNoDelete() (string, bool) {
	if len(fw.deleted) > 0 {
		return fmt.Sprintf("Expected no delete, got %v", fw.deleted), false
	}
	return "", true
}

func (fw *fakeEPWatcher) assertDelete(e *types.CiliumEndpoint) (string, bool) {
	var latest *types.CiliumEndpoint
	if len(fw.deleted) > 0 {
		latest = fw.deleted[len(fw.deleted)-1]
	}
	if !epEqual(latest, e) {
		return fmt.Sprintf("Expected no delete, got %s", epToString(latest)), false
	}
	return "", true
}

type fakeEndpointCache struct{}

func (fe *fakeEndpointCache) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	return nil
}

func createCES(name, namespace string, endpoints []v2alpha1.CoreCiliumEndpoint) *v2alpha1.CiliumEndpointSlice {
	return &v2alpha1.CiliumEndpointSlice{
		Namespace: namespace,
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
		Endpoints: endpoints,
	}
}

func createEndpoint(name, namespace string, id int64) *types.CiliumEndpoint {
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
	fakeEPWatcher := createFakeEPWatcher()
	fakeEndpointCache := &fakeEndpointCache{}
	cesSub := &cesSubscriber{
		epWatcher: fakeEPWatcher,
		epCache:   fakeEndpointCache,
		cepMap:    newCEPToCESMap(),
	}
	// Add for new CES
	cesSub.OnAdd(
		createCES("new-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{
			{
				Name:       cepName,
				IdentityID: newCEPID,
			},
		}))
	diff, ok := fakeEPWatcher.assertUpdate(endpointUpdate{
		NewEP: createEndpoint("cep1", "ns1", newCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	// Add for old CES
	cesSub.OnAdd(
		createCES("old-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{
			{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		}))
	diff, ok = fakeEPWatcher.assertUpdate(endpointUpdate{
		OldEP: createEndpoint("cep1", "ns1", newCEPID),
		NewEP: createEndpoint("cep1", "ns1", oldCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	// Delete the old CES
	cesSub.OnDelete(
		createCES("old-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{
			{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		}))
	diff, ok = fakeEPWatcher.assertUpdate(endpointUpdate{
		OldEP: createEndpoint("cep1", "ns1", oldCEPID),
		NewEP: createEndpoint("cep1", "ns1", newCEPID),
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
			"new-ces": createEndpoint("cep1", "ns1", 3),
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
	fakeEPWatcher := createFakeEPWatcher()
	fakeEndpointCache := &fakeEndpointCache{}
	cesSub := &cesSubscriber{
		epWatcher: fakeEPWatcher,
		epCache:   fakeEndpointCache,
		cepMap:    newCEPToCESMap(),
	}
	// Add for old CES
	cesSub.OnAdd(
		createCES("old-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{
			{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		}))
	diff, ok := fakeEPWatcher.assertUpdate(endpointUpdate{
		NewEP: createEndpoint("cep1", "ns1", oldCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	// Update for old CES removing CEP
	cesSub.OnUpdate(
		createCES("old-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{
			{
				Name:       cepName,
				IdentityID: oldCEPID,
			},
		}),
		createCES("old-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{}))

	diff, ok = fakeEPWatcher.assertDelete(createEndpoint("cep1", "ns1", oldCEPID))
	if !ok {
		t.Fatal(diff)
	}
	// Update for new CES
	cesSub.OnUpdate(
		createCES("new-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{}),
		createCES("new-ces", cepNamespace, []v2alpha1.CoreCiliumEndpoint{
			{
				Name:       cepName,
				IdentityID: newCEPID,
			},
		}))
	diff, ok = fakeEPWatcher.assertUpdate(endpointUpdate{
		NewEP: createEndpoint("cep1", "ns1", newCEPID),
	})
	if !ok {
		t.Fatal(diff)
	}
	wantCEPMap := map[string]cesToCEPRef{
		"ns1/cep1": {
			"new-ces": createEndpoint("cep1", "ns1", 3),
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
					"ces1": createEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "ces1"},
			deletedCesName: "ces1",
			deletedCep:     createEndpoint("cep1", "ns1", 3),
			expectedDelete: createEndpoint("cep1", "ns1", 3),
		},
		{
			desc: "delete CEP triggers update",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"ces1": createEndpoint("cep1", "ns1", 2),
					"ces2": createEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "ces1"},
			deletedCesName: "ces1",
			deletedCep:     createEndpoint("cep1", "ns1", 2),
			expectedUpdate: endpointUpdate{
				OldEP: createEndpoint("cep1", "ns1", 2),
				NewEP: createEndpoint("cep1", "ns1", 3),
			},
		},
		{
			desc: "delete CEP triggers no update or deletion",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"ces1": createEndpoint("cep1", "ns1", 1),
					"ces2": createEndpoint("cep1", "ns1", 2),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "ces1"},
			deletedCesName: "ces2",
			deletedCep:     createEndpoint("cep1", "ns1", 2),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			fakeEPWatcher := createFakeEPWatcher()
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
			diff, ok = fakeEPWatcher.assertDelete(tc.expectedDelete)
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
			cep:     createEndpoint("cep1", "ns1", 3),
			cesName: "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "update cep object",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cep:            createEndpoint("cep1", "ns1", 1),
			cesName:        "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 1),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "add new ces for existing cep",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cep:            createEndpoint("cep1", "ns1", 1),
			cesName:        "cesy",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
					"cesy": createEndpoint("cep1", "ns1", 1),
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
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep1",
			cesName:        "cesy",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "missing cep does not delete any entries",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep2",
			cesName:        "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
				},
			},
			wantCurrentCES: map[string]string{"ns1/cep1": "cesx"},
		},
		{
			desc: "last ces entry",
			initCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesx": createEndpoint("cep1", "ns1", 3),
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
					"cesx": createEndpoint("cep1", "ns1", 3),
					"cesy": createEndpoint("cep1", "ns1", 2),
				},
			},
			initCurrentCES: map[string]string{"ns1/cep1": "cesx"},
			cepName:        "ns1/cep1",
			cesName:        "cesx",
			wantCEPMap: map[string]cesToCEPRef{
				"ns1/cep1": {
					"cesy": createEndpoint("cep1", "ns1", 2),
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
		ces        *v2alpha1.CiliumEndpointSlice
		expectAdds []endpointUpdate
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "one_cep",
			ces: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{Name: "cep1"},
			}),
			expectAdds: []endpointUpdate{
				{NewEP: createEndpoint("cep1", testNamespace, 0)},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
			},
		},
		{
			name: "two_ceps",
			ces: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{Name: "cep1"},
				{Name: "cep2"},
			}),
			expectAdds: []endpointUpdate{
				{NewEP: createEndpoint("cep1", testNamespace, 0)},
				{NewEP: createEndpoint("cep2", testNamespace, 0)},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := createFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   &fakeEndpointCache{},
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
		newCES, oldCES *v2alpha1.CiliumEndpointSlice
		expectUpdates  []endpointUpdate
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "update_all",
			oldCES: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{
					Name:       "cep1",
					IdentityID: 1,
				},
				{
					Name:       "cep2",
					IdentityID: 1,
				},
			}),
			newCES: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{
					Name:       "cep1",
					IdentityID: 2,
				},
				{
					Name:       "cep2",
					IdentityID: 2,
				},
			}),
			expectUpdates: []endpointUpdate{
				{
					OldEP: createEndpoint("cep1", testNamespace, 1),
					NewEP: createEndpoint("cep1", testNamespace, 2),
				},
				{
					OldEP: createEndpoint("cep2", testNamespace, 1),
					NewEP: createEndpoint("cep2", testNamespace, 2),
				},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "update_one",
			oldCES: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{
					Name:       "cep1",
					IdentityID: 1,
				},
				{
					Name:       "cep2",
					IdentityID: 1,
				},
			}),
			newCES: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{
					Name:       "cep1",
					IdentityID: 2,
				},
				{
					Name:       "cep2",
					IdentityID: 1,
				},
			}),
			expectUpdates: []endpointUpdate{
				{
					OldEP: createEndpoint("cep1", testNamespace, 1),
					NewEP: createEndpoint("cep1", testNamespace, 2),
				},
			},
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
		{
			name: "no_changes",
			oldCES: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{Name: "cep1"},
				{Name: "cep2"},
			}),
			newCES: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{Name: "cep1"},
				{Name: "cep2"},
			}),
			expectedCurrentCES: map[string]string{
				"default/cep1": "ces",
				"default/cep2": "ces",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := createFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   &fakeEndpointCache{},
				cepMap:    m,
			}
			// Initialize state, but do not record the events.
			subscriber.OnAdd(tc.oldCES)
			watcher.reset()

			subscriber.OnUpdate(tc.oldCES, tc.newCES)

			if diff := cmp.Diff(tc.expectUpdates, watcher.updates, cmpopts.SortSlices(updateLess)); diff != "" {
				t.Errorf("Unexpected CEP updates(s) (-want +got):\n%s", diff)
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
		ces           *v2alpha1.CiliumEndpointSlice
		expectDeleted []*types.CiliumEndpoint
		// Expected cepToCESmap.expectedCurrentCES
		expectedCurrentCES map[string]string
	}{
		{
			name: "one_cep",
			ces: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{Name: "cep1"},
			}),
			expectDeleted: []*types.CiliumEndpoint{
				createEndpoint("cep1", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{},
		},
		{
			name: "two_ceps",
			ces: createCES("ces", testNamespace, []v2alpha1.CoreCiliumEndpoint{
				{Name: "cep1"},
				{Name: "cep2"},
			}),
			expectDeleted: []*types.CiliumEndpoint{
				createEndpoint("cep1", testNamespace, 0),
				createEndpoint("cep2", testNamespace, 0),
			},
			expectedCurrentCES: map[string]string{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			watcher := createFakeEPWatcher()
			m := &cepToCESmap{
				cepMap:     make(map[string]cesToCEPRef),
				currentCES: make(map[string]string),
			}
			subscriber := &cesSubscriber{
				epWatcher: watcher,
				epCache:   &fakeEndpointCache{},
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
