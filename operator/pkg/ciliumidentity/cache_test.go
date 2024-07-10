// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/labels"

	"github.com/stretchr/testify/assert"

	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/identity/key"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/labelsfilter"
)

var (
	k8sLables_A           = map[string]string{"a1": "1", "a2": "2"}
	k8sLables_B           = map[string]string{"b1": "1", "b2": "2"}
	k8sLables_B_duplicate = map[string]string{"b1": "1", "b2": "2"}
	k8sLables_C           = map[string]string{"c1": "1", "c2": "2"}
)

func TestMain(m *testing.M) {
	labelsfilter.ParseLabelPrefixCfg(nil, nil, "")

	os.Exit(m.Run())
}

func TestCIDState(t *testing.T) {
	// The subtests below share the same state to serially test insert, lookup and
	// remove operations of CIDState.
	state := NewCIDState()
	k1 := key.GetCIDKeyFromLabels(k8sLables_A, labels.LabelSourceK8s)
	k2 := key.GetCIDKeyFromLabels(k8sLables_B, labels.LabelSourceK8s)
	k3 := key.GetCIDKeyFromLabels(k8sLables_B_duplicate, labels.LabelSourceK8s)

	t.Run("Insert into CID state", func(t *testing.T) {
		state.Upsert("1", k1)
		expectedState := &CIDState{
			idToLabels: map[string]*key.GlobalIdentity{"1": k1},
			labelsToID: map[string]*SecIDs{
				k1.GetKey(): {
					selectedID: "1",
					ids:        map[string]struct{}{"1": {}},
				},
			},
		}

		assert.NoError(t, validateCIDState(state, expectedState), "cid 1 added")

		state.Upsert("2", k2)
		expectedState = &CIDState{
			idToLabels: map[string]*key.GlobalIdentity{"1": k1, "2": k2},
			labelsToID: map[string]*SecIDs{
				k1.GetKey(): {
					selectedID: "1",
					ids:        map[string]struct{}{"1": {}},
				},
				k2.GetKey(): {
					selectedID: "2",
					ids:        map[string]struct{}{"2": {}},
				},
			},
		}

		assert.NoError(t, validateCIDState(state, expectedState), "cid 2 added")

		state.Upsert("3", k3)
		expectedState = &CIDState{
			idToLabels: map[string]*key.GlobalIdentity{"1": k1, "2": k2, "3": k3},
			labelsToID: map[string]*SecIDs{
				k1.GetKey(): {
					selectedID: "1",
					ids:        map[string]struct{}{"1": {}},
				},
				k2.GetKey(): {
					selectedID: "2",
					ids:        map[string]struct{}{"2": {}, "3": {}},
				},
			},
		}

		assert.NoError(t, validateCIDState(state, expectedState), "cid 3 added - duplicate")
	})

	t.Run("Lookup CID state", func(t *testing.T) {
		_, exists := state.LookupByID("0")
		assert.Equal(t, false, exists, "cid 0 LookupByID - not found")

		cidKey, exists := state.LookupByID("1")
		assert.Equal(t, true, exists, "cid 1 LookupByID - found")
		assert.Equal(t, key.GetCIDKeyFromLabels(k8sLables_A, labels.LabelSourceK8s), cidKey, "cid 1 LookupByID - correct key")

		_, exists = state.LookupByKey(key.GetCIDKeyFromLabels(k8sLables_C, labels.LabelSourceK8s))
		assert.Equal(t, false, exists, "labels C LookupByKey - not found")

		cidName, exists := state.LookupByKey(key.GetCIDKeyFromLabels(k8sLables_A, labels.LabelSourceK8s))
		assert.Equal(t, true, exists, "labels C LookupByKey - not found")
		assert.Equal(t, "1", cidName, "labels C LookupByKey - correct CID")
	})

	t.Run("Remove from CID state", func(t *testing.T) {
		state.Remove("2")
		expectedState := &CIDState{
			idToLabels: map[string]*key.GlobalIdentity{"1": k1, "3": k3},
			labelsToID: map[string]*SecIDs{
				k1.GetKey(): {
					selectedID: "1",
					ids:        map[string]struct{}{"1": {}},
				},
				k2.GetKey(): {
					selectedID: "3",
					ids:        map[string]struct{}{"3": {}},
				},
			},
		}

		assert.NoError(t, validateCIDState(state, expectedState), "cid 2 removed")

		_, exists := state.LookupByID("2")
		assert.Equal(t, false, exists, "cid 2 LookupByID - not found")

		state.Remove("3")
		expectedState = &CIDState{
			idToLabels: map[string]*key.GlobalIdentity{"1": k1},
			labelsToID: map[string]*SecIDs{
				k1.GetKey(): {
					selectedID: "1",
					ids:        map[string]struct{}{"1": {}},
				},
			},
		}
		assert.NoError(t, validateCIDState(state, expectedState), "cid 3 removed")
	})
}

func TestCIDStateThreadSafety(t *testing.T) {
	// This test ensures that no changes to the CID state break its thread safety.
	// Multiple go routines in parallel continuously keep using CIDState.
	state := NewCIDState()

	k := key.GetCIDKeyFromLabels(k8sLables_A, labels.LabelSourceK8s)
	k2 := key.GetCIDKeyFromLabels(k8sLables_B, labels.LabelSourceK8s)

	wg := sync.WaitGroup{}
	queryStateFunc := func() {
		for i := 0; i < 500; i++ {
			state.LookupByID("1000")
			state.Upsert("1000", k)
			state.LookupByKey(k)
			state.Upsert("2000", k2)
			state.Remove("1000")
			state.LookupByID("2000")
		}

		wg.Done()
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go queryStateFunc()
	}

	wg.Wait()
}

func validateCIDState(state, expectedState *CIDState) error {
	if !reflect.DeepEqual(state.idToLabels, expectedState.idToLabels) {
		return fmt.Errorf("failed to validate the state, expected idToLabels %v, got %v", expectedState.idToLabels, state.idToLabels)
	}

	if !reflect.DeepEqual(state.labelsToID, expectedState.labelsToID) {
		return fmt.Errorf("failed to validate the state, expected labelsToID %v, got %v", expectedState.labelsToID, state.labelsToID)
	}

	return nil
}

func TestCIDUsageInPods(t *testing.T) {
	state := NewCIDUsageInPods()

	assertTxt := "Empty state"
	cidName1 := "1000"
	podName1 := "pod1"
	assert.Equal(t, 0, state.CIDUsageCount(cidName1), assertTxt)

	usedCID, exists := state.podToCID[podName1]
	assert.Equal(t, false, exists, assertTxt)
	assert.Equal(t, "", usedCID, assertTxt)

	prevCID, count, err := state.RemovePod(podName1)
	assert.Error(t, err)
	assert.Equal(t, "", prevCID, assertTxt)
	assert.Equal(t, 0, count, assertTxt)

	assertTxt = "Assign CID to Pod 1"
	prevCID, count = state.AssignCIDToPod(podName1, cidName1)
	assert.Equal(t, "", prevCID, assertTxt)
	assert.Equal(t, 0, count, assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount(cidName1), assertTxt)

	usedCID, exists = state.podToCID[podName1]
	assert.Equal(t, true, exists, assertTxt)
	assert.Equal(t, cidName1, usedCID, assertTxt)

	assertTxt = "Assign CID to Pod 2"
	podName2 := "pod2"
	prevCID, count = state.AssignCIDToPod(podName2, cidName1)
	assert.Equal(t, "", prevCID, assertTxt)
	assert.Equal(t, 0, count, assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount(cidName1), assertTxt)

	usedCID, exists = state.podToCID[podName2]
	assert.Equal(t, true, exists, assertTxt)
	assert.Equal(t, cidName1, usedCID, assertTxt)

	assertTxt = "Assign CID 2 to Pod 2"
	cidName2 := "2000"
	prevCID, count = state.AssignCIDToPod(podName2, cidName2)
	assert.Equal(t, cidName1, prevCID, assertTxt)
	assert.Equal(t, 1, count, assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount(cidName2), assertTxt)

	usedCID, exists = state.podToCID[podName2]
	assert.Equal(t, true, exists, assertTxt)
	assert.Equal(t, cidName2, usedCID, assertTxt)

	assertTxt = "Assign CID 2 to Pod 1"
	prevCID, count = state.AssignCIDToPod(podName1, cidName2)
	assert.Equal(t, cidName1, prevCID, assertTxt)
	assert.Equal(t, 0, count, assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount(cidName2), assertTxt)
	assert.Equal(t, 0, state.CIDUsageCount(cidName1), assertTxt)

	usedCID, exists = state.podToCID[podName1]
	assert.Equal(t, true, exists, assertTxt)
	assert.Equal(t, cidName2, usedCID, assertTxt)

	assertTxt = "Again assign CID 2 to Pod 1"
	prevCID, count = state.AssignCIDToPod(podName1, cidName2)
	assert.Equal(t, cidName2, prevCID, assertTxt)
	assert.Equal(t, 2, count, assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount(cidName2), assertTxt)
	assert.Equal(t, 0, state.CIDUsageCount(cidName1), assertTxt)

	assertTxt = "Remove Pod 1"
	prevCID, count, err = state.RemovePod(podName1)
	assert.NoError(t, err)
	assert.Equal(t, cidName2, prevCID, assertTxt)
	assert.Equal(t, 1, count, assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount(cidName2), assertTxt)

	usedCID, exists = state.podToCID[podName1]
	assert.Equal(t, false, exists, assertTxt)
	assert.Equal(t, "", usedCID, assertTxt)

	assertTxt = "Remove Pod 2"
	prevCID, count, err = state.RemovePod(podName2)
	assert.NoError(t, err)
	assert.Equal(t, cidName2, prevCID, assertTxt)
	assert.Equal(t, 0, count, assertTxt)
	assert.Equal(t, 0, state.CIDUsageCount(cidName2), assertTxt)

	usedCID, exists = state.podToCID[podName2]
	assert.Equal(t, false, exists, assertTxt)
	assert.Equal(t, "", usedCID, assertTxt)
}

func TestCIDUsageInCES(t *testing.T) {
	cep1 := cestest.CreateManagerEndpoint("cep1", 1000)
	cep2 := cestest.CreateManagerEndpoint("cep2", 1000)
	cep3 := cestest.CreateManagerEndpoint("cep3", 2000)
	cep4 := cestest.CreateManagerEndpoint("cep4", 3000)
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})

	cep5 := cestest.CreateManagerEndpoint("cep5", 1000)
	cep6 := cestest.CreateManagerEndpoint("cep6", 1000)
	cep7 := cestest.CreateManagerEndpoint("cep7", 2000)
	ces2 := cestest.CreateStoreEndpointSlice("ces2", "ns", []capi_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})

	assertTxt := "CES 1 is added"
	state := NewCIDUsageInCES()
	unusedCIDs := state.ProcessCESUpsert(ces1.Name, ces1.Endpoints)
	assert.Equal(t, 0, len(unusedCIDs), assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount("1000"), assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount("2000"), assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount("3000"), assertTxt)

	assertTxt = "CES 2 is added"
	unusedCIDs = state.ProcessCESUpsert(ces2.Name, ces2.Endpoints)
	assert.Equal(t, 0, len(unusedCIDs), assertTxt)
	assert.Equal(t, 4, state.CIDUsageCount("1000"), assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount("2000"), assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount("3000"), assertTxt)

	assertTxt = "Endpoint with CID 3000 is removed from CES 1"
	ces1 = cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3})
	unusedCIDs = state.ProcessCESUpsert(ces1.Name, ces1.Endpoints)
	assert.Equal(t, 1, len(unusedCIDs), assertTxt)
	if len(unusedCIDs) > 0 {
		assert.Equal(t, int64(3000), unusedCIDs[0], assertTxt)
	}
	assert.Equal(t, 4, state.CIDUsageCount("1000"), assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount("2000"), assertTxt)
	assert.Equal(t, 0, state.CIDUsageCount("3000"), assertTxt)

	assertTxt = "CES 1 is removed"
	unusedCIDs = state.ProcessCESDelete(ces1.Name, ces1.Endpoints)
	assert.Equal(t, 0, len(unusedCIDs), assertTxt)
	assert.Equal(t, 2, state.CIDUsageCount("1000"), assertTxt)
	assert.Equal(t, 1, state.CIDUsageCount("2000"), assertTxt)

	assertTxt = "CES 2 is removed"
	unusedCIDs = state.ProcessCESDelete(ces1.Name, ces1.Endpoints)
	assert.Equal(t, 2, len(unusedCIDs), assertTxt)
	assert.Equal(t, 0, state.CIDUsageCount("1000"), assertTxt)
	assert.Equal(t, 0, state.CIDUsageCount("2000"), assertTxt)
}
