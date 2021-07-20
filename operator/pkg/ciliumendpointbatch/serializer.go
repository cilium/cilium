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
	"github.com/cilium/cilium/pkg/lock"
)

type CebEventType string

const (
	// CebCreate is an event. it tells aggregator, to create a CEB with k8s-apiserver
	// in next CEBUpsert reconcile sync.
	CebCreate CebEventType = "CebsToCreate"
	// CebUpdate is an event. it tells aggregator, to update a CEB with k8s-apiserver
	// in next CEBUpsert reconcile sync.
	CebUpdate = "CebsToUpdate"
	// CebLazyUpdate is an event. it tells aggregator, to update a CEB with k8s-apiserver
	// in next CEBDelete reconcile sync.
	CebLazyUpdate = "CebsLazyUpdate"
	// CebDelete is an event. it tells aggregator, to delete a CEB with k8s-apiserver
	// in next CEBDelete reconcile sync.
	CebDelete = "CebsToDelete"
)

// aggregator is used to aggregate CEB events and resolve them into a single actionable item for the CEB.
// CEB manager watches for CEP updates and enqueue or dequeue them in different CEB's and calls updateAggregator function.
// aggregator job is to track what changes happened to a CEB and converge into a single update for reconcile purpose.
type aggregator struct {
	// cebsCreate is a set of CEB names, contains list of CEB's to be created in next
	// CEBUpsertSync reconcile period.
	cebsCreate map[string]struct{}
	// cebsUpdate is a set of CEB names, contains list of CEB's to be updated in next
	// CEBUpsertSync reconcile period.
	// This cebsUpdate set may contains following CEB's. If,
	// 1) New CEP is inserted into the CEB or
	// 2) Existing CEP values are modified in the CEB.
	cebsUpdate map[string]struct{}
	// cebsLazyUpdate is a set of CEB names, contains list of CEB's to be updated in
	// next CEBDeleteSync reconcile period.
	// This CEB lazyUpdate set contains following CEB's. If,
	// 1) Only CEPs are removed from this CEB.
	cebsLazyUpdate map[string]struct{}
	// cebsDelete is a set, contains list of CEB's to be deleted in next CEBDeleteSync reconcile period.
	cebsDelete map[string]struct{}
	syncMutex  lock.RWMutex
}

// Create and Initialize a aggregator
func newAggregator() *aggregator {

	return &aggregator{
		cebsCreate:     make(map[string]struct{}),
		cebsUpdate:     make(map[string]struct{}),
		cebsLazyUpdate: make(map[string]struct{}),
		cebsDelete:     make(map[string]struct{}),
	}

}

// updateAggregator receives CEBName and event for various CEB's, it would converge
// those requests into a single actionable item for a CEB.
//
// There are 4 different states, Create, Update, LazyUpdate and Delete and there are
// four events CebDelete, CebCreate, CebUpdate and CebLazyUpdate.
//
// Based on the given event, CEB is placed in one of the state. Below is state machine for Delete state,
//
// Input-Event         Current-State     Output-State
//  CebDelete               NA               Delete
//  CebDelete             Delete             Delete
//  CebCreate             Delete             Delete
//  CebUpdate             Delete             Delete
//  CebLazyUpdate         Delete             Delete
// Delete is special state, its terminal state. Once CEB is marked for delete, then client
// cannot queue anymore CEPs in that CEB. Eventually this would be removed from api-server and local cache.
//
// State machine for Create state,
//
// Input-Event         Current-State     Output-State
//  CebCreate               NA               Create
//  CebDelete             Create             Delete
//  CebCreate             Create             Create
//  CebUpdate             Create             Create
//  CebLazyUpdate         Create             Create
// As long as if CEB is not marked for Delete. It shall be marked for Create.
//
// State machine for Update state,
//
// Input-Event         Current-State     Output-State
//  CebUpdate               NA               Update
//  CebDelete             Update             Delete
//  CebCreate             Update             Create
//  CebUpdate             Update             Update
//  CebLazyUpdate         Update             Update
// As long as if CEB is not marked for Delete and Create. It shall be marked for Update.
//
// State machine for Update state,
//
// Input-Event         Current-State     Output-State
//  CebLazyUpdate           NA            CebLazyUpdate
//  CebDelete          CebLazyUpdate         Delete
//  CebCreate          CebLazyUpdate         Create
//  CebUpdate          CebLazyUpdate         Update
//  CebLazyUpdate      CebLazyUpdate      CebLazyUpdate
// As long as if CEB is not marked for Delete, Create and Update. It shall be marked for LazyUpdate.
//
// For example, if CEB is created locally, any client of Aggregator calls updateAggregator with cebName
// and event type. updateAggregator, looks up current state of CEB and determines the right state for that CEB
//
// For ex. Client might send following request to the aggregator in this format [cebName-CebEvent]
// xyz-CebCreate, xyz-CebUpdate, xyz-CebDelete
// abc-CebCreate, abc-CebUpdate, abc-CebUpdate, abc-CebLazyUpdate
// klm-CebLazyUpdate, klm-CebLazyUpdate, klm-CebUpdate
// These requests are resolved into xyz-Delete, abc-Create and klm-Update
// CebDelete: takes precedence over other all requests.
// CebCreate: takes precedence over CebUpdate and CebLazyUpdate.
// CebUpdate: takes precedence over CebLazyUpdate.
// Note: If CEB is marked for delete, Client wouldn't send any more requests for that CEB.

func (s *aggregator) updateAggregator(cebName string, sync CebEventType) {
	log.Debugf("updateAggregator Ceb Name:%s Type:%s", cebName, sync)
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	switch sync {
	case CebDelete:
		// mark the ceb for Delete
		s.cebsDelete[cebName] = struct{}{}
		// Remove ceb from other sets.
		if _, ok := s.cebsCreate[cebName]; ok {
			delete(s.cebsCreate, cebName)
		}
		if _, ok := s.cebsUpdate[cebName]; ok {
			delete(s.cebsUpdate, cebName)
		}
		if _, ok := s.cebsLazyUpdate[cebName]; ok {
			delete(s.cebsLazyUpdate, cebName)
		}

	case CebCreate:
		//  mark the ceb for Create.
		// If the CEB is already marked in Delete, skip inserting in Create.
		if _, ok := s.cebsDelete[cebName]; !ok {
			s.cebsCreate[cebName] = struct{}{}
		}
		// Remove ceb from other buckets.
		// There are couple of reason why we need to remove from other sets.
		// 1) We don't want any duplicate request for a given CEB.
		// 2) If reconciler is failed to Create CEBs in past reconcile syncs, those CEB's are sent back to
		// aggregator to sync during next cycle. so we may notice CebCreate requests at any point of time.
		if _, ok := s.cebsUpdate[cebName]; ok {
			log.Debugf("Ceb:%s got create request but was already marked up for update", cebName)
			delete(s.cebsUpdate, cebName)
		}
		if _, ok := s.cebsLazyUpdate[cebName]; ok {
			log.Debugf("Ceb:%s got create request but was already marked up for Lazyupdate", cebName)
			delete(s.cebsLazyUpdate, cebName)
		}

	case CebUpdate:
		_, createOk := s.cebsCreate[cebName]
		_, deleteOk := s.cebsDelete[cebName]
		// mark the ceb for Update.
		// If the CEB is already queued in Create or Delete, skip inserting in Update.
		if !createOk && !deleteOk {
			s.cebsUpdate[cebName] = struct{}{}
		}
		// If Ceb, is already queued up in LazyUpdate and remove from LazyUpdate.
		if _, ok := s.cebsLazyUpdate[cebName]; ok {
			log.Debugf("Ceb:%s got update request but was already marked up for Lazyupdate", cebName)
			delete(s.cebsLazyUpdate, cebName)
		}

	case CebLazyUpdate:
		_, createOk := s.cebsCreate[cebName]
		_, updateOk := s.cebsUpdate[cebName]
		_, deleteOk := s.cebsDelete[cebName]
		// Insert the ceb in Lazy update, if not in Create, Update or Delete.
		if !createOk && !updateOk && !deleteOk {
			s.cebsLazyUpdate[cebName] = struct{}{}
		}
	default:
		log.Infof("Invalid type aggregator: %v", sync)
	}
	return
}

// Returns the list of CreateCebs and UpdateCebs
func (s *aggregator) getCreateAndUpdateCebNames() (cebsCreate []string, cebsUpdate []string) {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	for c := range s.cebsCreate {
		cebsCreate = append(cebsCreate, c)
		delete(s.cebsCreate, c)
	}

	for c := range s.cebsUpdate {
		cebsUpdate = append(cebsUpdate, c)
		delete(s.cebsUpdate, c)
	}

	return
}

// Returns the list of CreateCebs, UpdateCebs and DeleteCebs
func (s *aggregator) getCreateUpdateAndDeleteCebNames() (cebsCreate []string, cebsUpdate []string, cebsDelete []string) {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	for c := range s.cebsCreate {
		cebsCreate = append(cebsCreate, c)
		delete(s.cebsCreate, c)
	}

	for c := range s.cebsUpdate {
		cebsUpdate = append(cebsUpdate, c)
		delete(s.cebsUpdate, c)
	}

	for c := range s.cebsDelete {
		cebsDelete = append(cebsDelete, c)
		delete(s.cebsDelete, c)
	}

	for c := range s.cebsLazyUpdate {
		cebsUpdate = append(cebsUpdate, c)
		delete(s.cebsLazyUpdate, c)
	}

	return
}

// Returns true if CEB is marked for Delete
func (s *aggregator) isCebMarkedForDelete(cebName string) bool {
	if _, ok := s.cebsDelete[cebName]; !ok {
		return false
	}

	return true
}
