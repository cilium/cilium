// Copyright 2018 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package cache

import (
	"context"
	"sort"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// NodeHash computes string identifiers for Envoy nodes.
type NodeHash interface {
	// ID function defines a unique string identifier for the remote Envoy node.
	ID(node *core.Node) string
}

// IDHash uses ID field as the node hash.
type IDHash struct{}

// ID uses the node ID field
func (IDHash) ID(node *core.Node) string {
	if node == nil {
		return ""
	}
	return node.GetId()
}

var _ NodeHash = IDHash{}

// StatusInfo publishes information about nodes that are watching the xDS cache.
type StatusInfo interface {
	// GetNode returns the node metadata.
	GetNode() *core.Node

	// GetNumWatches returns the number of open watches.
	GetNumWatches() int

	// GetNumDeltaWatches returns the number of open delta watches.
	GetNumDeltaWatches() int

	// GetLastWatchRequestTime returns the timestamp of the last discovery watch request.
	GetLastWatchRequestTime() time.Time

	// GetLastDeltaWatchRequestTime returns the timestamp of the last delta discovery watch request.
	GetLastDeltaWatchRequestTime() time.Time
}

// statusInfo tracks the server state for the remote Envoy node.
type statusInfo struct {
	// node is the constant Envoy node metadata.
	node *core.Node

	// watches are indexed channels for the response watches and the original requests.
	watches        map[int64]ResponseWatch
	orderedWatches keys

	// deltaWatches are indexed channels for the delta response watches and the original requests
	deltaWatches        map[int64]DeltaResponseWatch
	orderedDeltaWatches keys

	// the timestamp of the last watch request
	lastWatchRequestTime time.Time

	// the timestamp of the last delta watch request
	lastDeltaWatchRequestTime time.Time

	// mutex to protect the status fields.
	// should not acquire mutex of the parent cache after acquiring this mutex.
	mu sync.RWMutex
}

type WatchResponse interface {
	GetReturnedResources() map[string]string
	GetResponseVersion() string
}

// ResponseWatch is a watch record keeping both the request and an open channel for the response.
type ResponseWatch struct {
	// Request is the original request for the watch.
	Request *Request

	// Response is the channel to push responses to.
	Response chan Response

	// Subscription stores the current client subscription state.
	subscription Subscription

	// fullStateResponses requires that all resources matching the request, with no regards to which ones actually updated, must be provided in the response.
	fullStateResponses bool
}

func (w ResponseWatch) isDelta() bool {
	return false
}

func (w ResponseWatch) useResourceVersion() bool {
	return false
}

func (w ResponseWatch) buildResponse(updatedResources []*cachedResource, _ []string, returnedVersions map[string]string, version string) WatchResponse {
	return &RawResponse{
		Request:           w.Request,
		resources:         updatedResources,
		returnedResources: returnedVersions,
		Version:           version,
		Ctx:               context.Background(),
	}
}

func (w ResponseWatch) sendFullStateResponses() bool {
	return w.fullStateResponses
}

func (w ResponseWatch) getSubscription() Subscription {
	return w.subscription
}

func (w ResponseWatch) sendResponse(resp WatchResponse) {
	w.Response <- resp.(*RawResponse)
}

// DeltaResponseWatch is a watch record keeping both the delta request and an open channel for the delta response.
type DeltaResponseWatch struct {
	// Request is the most recent delta request for the watch
	Request *DeltaRequest

	// Response is the channel to push the delta responses to
	Response chan DeltaResponse

	// Subscription stores the current client subscription state.
	subscription Subscription
}

func (w DeltaResponseWatch) isDelta() bool {
	return true
}

func (w DeltaResponseWatch) useResourceVersion() bool {
	return true
}

func (w DeltaResponseWatch) sendFullStateResponses() bool {
	return false
}

func (w DeltaResponseWatch) getSubscription() Subscription {
	return w.subscription
}

func (w DeltaResponseWatch) buildResponse(updatedResources []*cachedResource, removedResources []string, returnedVersions map[string]string, version string) WatchResponse {
	return &RawDeltaResponse{
		DeltaRequest:      w.Request,
		resources:         updatedResources,
		removedResources:  removedResources,
		returnedResources: returnedVersions,
		SystemVersionInfo: version,
		Ctx:               context.Background(),
	}
}

func (w DeltaResponseWatch) sendResponse(resp WatchResponse) {
	w.Response <- resp.(*RawDeltaResponse)
}

// newStatusInfo initializes a status info data structure.
func newStatusInfo(node *core.Node) *statusInfo {
	out := statusInfo{
		node:           node,
		watches:        make(map[int64]ResponseWatch),
		orderedWatches: make(keys, 0),
		deltaWatches:   make(map[int64]DeltaResponseWatch),
	}
	return &out
}

func (info *statusInfo) GetNode() *core.Node {
	info.mu.RLock()
	defer info.mu.RUnlock()
	return info.node
}

func (info *statusInfo) GetNumWatches() int {
	info.mu.RLock()
	defer info.mu.RUnlock()
	return len(info.watches)
}

func (info *statusInfo) GetNumDeltaWatches() int {
	info.mu.RLock()
	defer info.mu.RUnlock()
	return len(info.deltaWatches)
}

func (info *statusInfo) GetLastWatchRequestTime() time.Time {
	info.mu.RLock()
	defer info.mu.RUnlock()
	return info.lastWatchRequestTime
}

func (info *statusInfo) GetLastDeltaWatchRequestTime() time.Time {
	info.mu.RLock()
	defer info.mu.RUnlock()
	return info.lastDeltaWatchRequestTime
}

// setLastDeltaWatchRequestTime will set the current time of the last delta discovery watch request.
func (info *statusInfo) setLastDeltaWatchRequestTime(t time.Time) {
	info.mu.Lock()
	defer info.mu.Unlock()
	info.lastDeltaWatchRequestTime = t
}

// setDeltaResponseWatch will set the provided delta response watch for the associated watch ID.
func (info *statusInfo) setDeltaResponseWatch(id int64, drw DeltaResponseWatch) {
	info.mu.Lock()
	defer info.mu.Unlock()
	info.deltaWatches[id] = drw
}

// orderResponseWatches will track a list of watch keys and order them if
// true is passed.
func (info *statusInfo) orderResponseWatches() {
	info.orderedWatches = make(keys, len(info.watches))

	var index int
	for id, watch := range info.watches {
		info.orderedWatches[index] = key{
			ID:      id,
			TypeURL: watch.Request.GetTypeUrl(),
		}
		index++
	}

	// Sort our list which we can use in the SetSnapshot functions.
	// This is only run when we enable ADS on the cache.
	sort.Sort(info.orderedWatches)
}

// orderResponseDeltaWatches will track a list of delta watch keys and order them if
// true is passed.
func (info *statusInfo) orderResponseDeltaWatches() {
	info.orderedDeltaWatches = make(keys, len(info.deltaWatches))

	var index int
	for id, deltaWatch := range info.deltaWatches {
		info.orderedDeltaWatches[index] = key{
			ID:      id,
			TypeURL: deltaWatch.Request.GetTypeUrl(),
		}
		index++
	}

	// Sort our list which we can use in the SetSnapshot functions.
	// This is only run when we enable ADS on the cache.
	sort.Sort(info.orderedDeltaWatches)
}
