// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nonglobal

import (
	"testing"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/stretchr/testify/assert"
)

var (
	testLblsA    = labels.Map2Labels(map[string]string{"key-a": "val-1"}, labels.LabelSourceK8s)
	testLblsB    = labels.Map2Labels(map[string]string{"key-b": "val-2"}, labels.LabelSourceK8s)
	testNumOfEps = 10

	nilID   *identity.Identity
	testEps []*endpoint.Endpoint
)

func testGCEndpointListerFunc() []*endpoint.Endpoint {
	return testEps
}

func testGenerateGCEndpointList() {
	testEps = []*endpoint.Endpoint{}
	for i := 0; i < testNumOfEps; i++ {
		testEps = append(testEps, &endpoint.Endpoint{})
	}
}

func TestTempSecIDAllocator(t *testing.T) {
	tempAllocator := NewTempSecIDAllocator(nil)
	id1, err := tempAllocator.FindOrCreateTempID(testLblsA)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, int(id1.ID), identity.DefaultMinTempID)
	assert.LessOrEqual(t, int(id1.ID), identity.DefaultMaxTempID)

	id2, err := tempAllocator.FindOrCreateTempID(testLblsA)
	assert.NoError(t, err)
	assert.Equal(t, id1, id2)

	id3, exists := tempAllocator.LookupByID(identity.NumericIdentity(id1.ID))
	assert.Equal(t, true, exists)
	assert.Equal(t, id3, id2)

	id4, exists := tempAllocator.LookupByIDKey(&key.GlobalIdentity{LabelArray: testLblsA.LabelArray()})
	assert.Equal(t, true, exists)
	assert.Equal(t, id4, id3)

	outOfBoundID := identity.NumericIdentity(1000)
	id5, exists := tempAllocator.LookupByID(outOfBoundID)
	assert.Equal(t, false, exists)
	assert.Equal(t, id5, nilID)

	id6, exists := tempAllocator.LookupByIDKey(&key.GlobalIdentity{LabelArray: testLblsB.LabelArray()})
	assert.Equal(t, false, exists)
	assert.Equal(t, id6, nilID)
}

func TestTempSecIDGC(t *testing.T) {
	tempAllocator := NewTempSecIDAllocator(testGCEndpointListerFunc)
	defer func() {
		testEps = []*endpoint.Endpoint{}
	}()

	min := identity.DefaultMinTempID
	max := identity.DefaultMaxTempID
	for i := 0; i < testNumOfEps; i++ {
		if i%2 == 0 {
			tempAllocator.insertToCache(&identity.Identity{ID: identity.NumericIdentity(min + i)})
		} else {
			tempAllocator.insertToCache(&identity.Identity{ID: identity.NumericIdentity(max - i)})
		}
	}

	assert.Equal(t, 10, len(tempAllocator.tempIDCache.idToIdentity))

	tempAllocator.runGC()
	tempAllocator.runGC()
	assert.Equal(t, 10, len(tempAllocator.tempIDCache.idToIdentity))

	testGenerateGCEndpointList()
	eps := testGCEndpointListerFunc()
	for i, ep := range eps {
		ep.SecurityIdentity = &identity.Identity{ID: identity.NumericIdentity(min + i)}
	}
	tempAllocator.runGC()
	assert.Equal(t, 10, len(tempAllocator.tempIDCache.idToIdentity))

	tempAllocator.runGC()
	assert.Equal(t, 5, len(tempAllocator.tempIDCache.idToIdentity))

	expectedID := &identity.Identity{ID: identity.NumericIdentity(min)}
	id1, exists := tempAllocator.LookupByID(identity.NumericIdentity(min))
	assert.Equal(t, true, exists)
	assert.Equal(t, expectedID, id1)

	testEps = testEps[1:]
	tempAllocator.runGC()
	id1, exists = tempAllocator.LookupByID(identity.NumericIdentity(min))
	assert.Equal(t, true, exists)
	assert.Equal(t, expectedID, id1)

	tempAllocator.runGC()
	id1, exists = tempAllocator.LookupByID(identity.NumericIdentity(min))
	assert.Equal(t, false, exists)
	assert.Equal(t, nilID, id1)
}
