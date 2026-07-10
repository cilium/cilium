// Copyright 2020 Envoyproxy Authors
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
	"fmt"
)

// MuxCache multiplexes across several caches using a classification function.
// If there is no matching cache for a classification result, the cache
// responds with an empty closed channel, which effectively terminates the
// stream on the server. It might be preferred to respond with a "nil" channel
// instead which will leave the stream open in case the stream is aggregated by
// making sure there is always a matching cache.
type MuxCache struct {
	// Classification functions.
	Classify      func(*Request) string
	ClassifyDelta func(*DeltaRequest) string
	// Muxed caches.
	Caches map[string]Cache
}

var _ Cache = &MuxCache{}

func (mux *MuxCache) CreateWatch(request *Request, sub Subscription, value chan Response) (func(), error) {
	key := mux.Classify(request)
	cache, exists := mux.Caches[key]
	if !exists {
		return nil, fmt.Errorf("no cache defined for key %s", key)
	}
	return cache.CreateWatch(request, sub, value)
}

func (mux *MuxCache) CreateDeltaWatch(request *DeltaRequest, sub Subscription, value chan DeltaResponse) (func(), error) {
	key := mux.ClassifyDelta(request)
	cache, exists := mux.Caches[key]
	if !exists {
		return nil, fmt.Errorf("no cache defined for key %s", key)
	}
	return cache.CreateDeltaWatch(request, sub, value)
}

func (mux *MuxCache) Fetch(ctx context.Context, request *Request) (Response, error) {
	key := mux.Classify(request)
	cache, exists := mux.Caches[key]
	if !exists {
		return nil, fmt.Errorf("no cache defined for key %s", key)
	}
	// Not all caches may implement Fetch; we delegate to the selected cache and if
	// it does not implement Fetch, it will return an error.
	return cache.Fetch(ctx, request)
}
