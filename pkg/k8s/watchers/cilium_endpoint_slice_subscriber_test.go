// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package watchers

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

type endpointUpdate struct {
	oldEp, newEp *types.CiliumEndpoint
}

func epToString(e *types.CiliumEndpoint) string {
	if e == nil {
		return "nil"
	}
	return fmt.Sprintf("ep(id: %d)", e.Identity.ID)
}

func (u endpointUpdate) toString() string {
	return fmt.Sprintf("(%s, %s)", epToString(u.oldEp), epToString(u.newEp))
}

func epEqual(e1, e2 *types.CiliumEndpoint) bool {
	return ((e1 == nil) == (e2 == nil)) && (e1 == nil || e1.Identity.ID == e2.Identity.ID)
}

func updateEqual(u1, u2 endpointUpdate) bool {
	return epEqual(u1.oldEp, u2.oldEp) && epEqual(u1.newEp, u2.newEp)
}

type fakeEPWatcher struct {
	lastUpdate endpointUpdate
	lastDelete *types.CiliumEndpoint
}

func createFakeEPWatcher() *fakeEPWatcher {
	return &fakeEPWatcher{}
}

func (fw *fakeEPWatcher) endpointUpdated(oldC, newC *types.CiliumEndpoint) {
	fw.lastUpdate = endpointUpdate{oldC, newC}
}

func (fw *fakeEPWatcher) endpointDeleted(c *types.CiliumEndpoint) {
	fw.lastDelete = c
}

func (fw *fakeEPWatcher) assertUpdate(u endpointUpdate) (string, bool) {
	if !updateEqual(fw.lastUpdate, u) {
		return fmt.Sprintf("Expected %s, got %s", u.toString(), fw.lastUpdate.toString()), false
	}
	return "", true
}

func (fw *fakeEPWatcher) assertNoDelete() (string, bool) {
	if fw.lastDelete != nil {
		return fmt.Sprintf("Expected no delete, got %s", epToString(fw.lastDelete)), false
	}
	return "", true
}

func (fw *fakeEPWatcher) assertDelete(e *types.CiliumEndpoint) (string, bool) {
	if !epEqual(fw.lastDelete, e) {
		return fmt.Sprintf("Expected no delete, got %s", epToString(fw.lastDelete)), false
	}
	return "", true
}

type fakeEndpointCache struct{}

func (fe *fakeEndpointCache) LookupPodName(namespacedName string) *endpoint.Endpoint {
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
		newEp: createEndpoint("cep1", "ns1", newCEPID),
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
		oldEp: createEndpoint("cep1", "ns1", newCEPID),
		newEp: createEndpoint("cep1", "ns1", oldCEPID),
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
		oldEp: createEndpoint("cep1", "ns1", oldCEPID),
		newEp: createEndpoint("cep1", "ns1", newCEPID),
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
		newEp: createEndpoint("cep1", "ns1", oldCEPID),
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
		newEp: createEndpoint("cep1", "ns1", newCEPID),
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
				oldEp: createEndpoint("cep1", "ns1", 2),
				newEp: createEndpoint("cep1", "ns1", 3),
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
