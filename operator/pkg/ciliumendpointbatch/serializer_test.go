// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ciliumendpointbatch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	// CebName  for testing purpose
	CebName = "ceb-orange-one1"
)

func TestUpdateAggregator(t *testing.T) {
	testCases := []struct {
		name    string
		cebName string
		reqs    []CebEventType
		res     CebEventType
	}{
		{
			name:    "Create, Update and Delete a CEB, this should converge to CebDelete",
			cebName: "ceb-apple-one1",
			reqs:    []CebEventType{CebCreate, CebUpdate, CebUpdate, CebUpdate, CebDelete},
			res:     CebDelete,
		},
		{
			name:    "Create, Delete and at last Update a CEB, this should converge to CebDelete",
			cebName: "ceb-apple-one2",
			reqs:    []CebEventType{CebCreate, CebUpdate, CebUpdate, CebUpdate, CebDelete, CebUpdate},
			res:     CebDelete,
		},
		{
			name:    "Update, Create and at last LazyUpdate a CEB, this should converge to CebCreate",
			cebName: "ceb-apple-one3",
			reqs:    []CebEventType{CebUpdate, CebUpdate, CebUpdate, CebUpdate, CebCreate, CebUpdate, CebLazyUpdate},
			res:     CebCreate,
		},
		{
			name:    "Create and Update a CEB, this should converge to CebCreate",
			cebName: "ceb-apple-two1",
			reqs:    []CebEventType{CebCreate, CebUpdate, CebUpdate, CebUpdate},
			res:     CebCreate,
		},
		{
			name:    "Only CEB Updates, this should converge to CebUpdate",
			cebName: "ceb-apple-two2",
			reqs:    []CebEventType{CebUpdate, CebUpdate, CebUpdate},
			res:     CebUpdate,
		},
		{
			name:    "Create, Update and LazyUpdate a CEB, this should converge to CebCreate",
			cebName: "ceb-apple-Three",
			reqs:    []CebEventType{CebCreate, CebUpdate, CebUpdate, CebUpdate, CebLazyUpdate},
			res:     CebCreate,
		},
		{
			name:    "Multiple CEB LazyUpdates, Updates and single Create, this should converge to CebCreate",
			cebName: "ceb-apple-four1",
			reqs:    []CebEventType{CebLazyUpdate, CebCreate, CebLazyUpdate, CebUpdate},
			res:     CebCreate,
		},
		{
			name:    "Multiple LazyUpdates and Updates, this should converge to a single Update",
			cebName: "ceb-apple-four2",
			reqs:    []CebEventType{CebUpdate, CebLazyUpdate, CebLazyUpdate, CebLazyUpdate},
			res:     CebUpdate,
		},
		{
			name:    "Multiple LazyUpdates and Single Update, this should converge to single Update",
			cebName: "ceb-apple-four3",
			reqs:    []CebEventType{CebLazyUpdate, CebLazyUpdate, CebLazyUpdate, CebUpdate, CebLazyUpdate, CebLazyUpdate, CebLazyUpdate},
			res:     CebUpdate,
		},
	}

	s := newAggregator()
	// Test updateAggregator with multiple events for a CEB.
	for _, tc := range testCases {
		t.Run(tc.name, func(*testing.T) {
			var res CebEventType
			t.Logf("Testing :%#v", tc.name)
			// pass all the events to aggregator
			for _, rs := range tc.reqs {
				s.updateAggregator(tc.cebName, rs)
			}
			// Get all CEBs and check for result
			cebCreate, cebUpdate, cebDelete := s.getCreateUpdateAndDeleteCebNames()

			for _, val := range cebCreate {
				if val == tc.cebName {
					res = CebCreate
				}
			}

			for _, val := range cebUpdate {
				if val == tc.cebName {
					res = CebUpdate
				}
			}

			for _, val := range cebDelete {
				if val == tc.cebName {
					res = CebDelete
				}
			}
			t.Logf("testing :%#v", tc.name)
			assert.Equal(t, res, tc.res, "Output should match with result")
		})
	}

	t.Run("Test Lazy updates", func(*testing.T) {
		s = newAggregator()
		// test UpdateAggregator with only lazyUpdates
		reqs := []CebEventType{CebLazyUpdate, CebLazyUpdate, CebLazyUpdate, CebLazyUpdate, CebLazyUpdate, CebLazyUpdate}
		for _, req := range reqs {
			s.updateAggregator(CebName, req)
		}
		// Create and Update list shouldn't have any CEBs in it.
		c, u := s.getCreateAndUpdateCebNames()
		assert.Equal(t, len(c), 0, "Nothing in for Create")
		assert.Equal(t, len(u), 0, "Nothing in for Update")

		// Update list  includes LazyUpdates and normal Updates.
		c, u, d := s.getCreateUpdateAndDeleteCebNames()
		assert.Equal(t, len(c), 0, "Nothing in for Create")
		assert.Equal(t, len(u), 1, "Lazy updates is part of Updates")
		assert.Equal(t, len(d), 0, "Nothing in for Delete")
	})
	t.Run("Test Empty Aggregator", func(*testing.T) {
		s = newAggregator()
		// Create and Update list shouldn't have any CEBs in it.
		c, u := s.getCreateAndUpdateCebNames()
		assert.Equal(t, len(c), 0, "Nothing in for Create")
		assert.Equal(t, len(u), 0, "Nothing in for Update")

		// Update list  includes LazyUpdates and normal Updates.
		c, u, d := s.getCreateUpdateAndDeleteCebNames()
		assert.Equal(t, len(c), 0, "Nothing in for Create")
		assert.Equal(t, len(u), 0, "Lazy updates is part of Updates")
		assert.Equal(t, len(d), 0, "Nothing in for Delete")

	})
}
