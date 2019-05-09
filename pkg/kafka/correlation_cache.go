// Copyright 2018 Authors of Cilium
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

package kafka

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

var (
	// RequestLifetime specifies the maximum time a request can stay in the
	// correlation cache without getting correlated. After this time has
	// passed, the request will be removed from the cache
	RequestLifetime = 5 * time.Minute
)

type requestsCache map[CorrelationID]*correlationEntry

// FinishFunc is the function called when a request has been correlated with
// its response
type FinishFunc func(req *RequestMessage)

// correlationEntry is the structure used to store requests in the correlation
// cache
type correlationEntry struct {
	request *RequestMessage

	// created is the timestamp when the request was created in the cache
	created time.Time

	// finishFunc is called when the request has been correlated with a
	// response or when the request has been expired from the cache
	finishFunc FinishFunc

	// origCorrelationID is the original correlation ID as present in the
	// request. It will be used to restore the correlation ID in the
	// response heading back to the client.
	origCorrelationID CorrelationID
}

// CorrelationCache is a cache used to correlate requests with responses
//
// It consists of two main functions:
//
// cache.HandleRequest(request)
//
//   Must be called when a request is forwarded to the broker, will keep track
//   of the request and rewrite the correlation ID inside of the request to
//   a sequence number. This sequence number is guaranteed to be unique within
//   the connection covered by the cache.
//
// cache.CorrelateResponse(response)
//
//   Must be called when a response is received from the broker. Will return
//   the original request that corresponds to the response and will restore the
//   correlation ID in the response to the value that was found in the original
//   request.
//
// A garbage collector will run frequently and expire requests which have not
// been correlated for the period of `RequestLifetime`
type CorrelationCache struct {
	// mutex protects the cache and numExpired
	mutex lock.RWMutex

	// cache is a list of all Kafka requests currently waiting to be
	// correlated with a response
	cache requestsCache

	// numExpired is the number of expired entries
	numExpired uint64

	// NumGcRuns counts the number of garbage collector runs
	numGcRuns uint64

	// nextSequenceNumber is the next sequence number to be used as
	// correlation ID
	nextSequenceNumber CorrelationID

	// stopGc is closed when the garbage collector must exit
	stopGc chan struct{}
}

// NewCorrelationCache returns a new correlation cache
func NewCorrelationCache() *CorrelationCache {
	cc := &CorrelationCache{
		cache:              requestsCache{},
		nextSequenceNumber: 1,
		stopGc:             make(chan struct{}),
	}

	go cc.garbageCollector()

	return cc
}

// DeleteCache releases the cache and stops the garbage collector. This
// function must be called when the cache is no longer required, otherwise go
// routines are leaked.
func (cc *CorrelationCache) DeleteCache() {
	close(cc.stopGc)
}

// HandleRequest must be called when a request is forwarded to the broker, will
// keep track of the request and rewrite the correlation ID inside of the
// request to a sequence number. This sequence number is guaranteed to be
// unique within the connection covered by the cache.
func (cc *CorrelationCache) HandleRequest(req *RequestMessage, finishFunc FinishFunc) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// save the original correlation ID
	origCorrelationID := req.GetCorrelationID()

	// Use a sequence number to generate a correlation ID that is
	// guaranteed to be unique
	newCorrelationID := cc.nextSequenceNumber
	cc.nextSequenceNumber++

	// Overwrite the correlation ID in the request to allow correlating the
	// response later on. The original correlation ID will be restored when
	// forwarding the response
	req.SetCorrelationID(newCorrelationID)

	if _, ok := cc.cache[newCorrelationID]; ok {
		log.Warning("BUG: Overwriting Kafka request message in correlation cache")
	}

	cc.cache[newCorrelationID] = &correlationEntry{
		request:           req,
		created:           time.Now(),
		origCorrelationID: origCorrelationID,
		finishFunc:        finishFunc,
	}
}

// correlate returns the request message with the matching correlation ID
func (cc *CorrelationCache) correlate(id CorrelationID) *correlationEntry {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	entry := cc.cache[id]
	return entry
}

// CorrelateResponse extracts the correlation ID from the response message,
// correlates the corresponding request, restores the original correlation ID
// in the response and returns the original request
func (cc *CorrelationCache) CorrelateResponse(res *ResponseMessage) *RequestMessage {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	correlationID := res.GetCorrelationID()
	if entry := cc.cache[correlationID]; entry != nil {
		res.SetCorrelationID(entry.origCorrelationID)

		if entry.finishFunc != nil {
			entry.finishFunc(entry.request)
		}

		delete(cc.cache, correlationID)
		return entry.request
	}

	return nil
}

func (cc *CorrelationCache) garbageCollector() {
	for {
		select {
		case <-cc.stopGc:
			return
		default:
		}

		// calculate the creation time for expiration, entries created
		// prior to this timestamp must be expired
		expiryCreationTime := time.Now().Add(-RequestLifetime)

		log.WithField("expiryCreationTime", expiryCreationTime).
			Debug("Running Kafka correlation cache garbage collector")

		cc.mutex.Lock()
		for correlationID, entry := range cc.cache {
			if entry.created.Before(expiryCreationTime) {
				log.WithField(fieldRequest, entry.request).Debug("Request expired in cache, removing")
				delete(cc.cache, correlationID)
				cc.numExpired++

				if entry.finishFunc != nil {
					entry.finishFunc(entry.request)
				}
			}
		}

		cc.numGcRuns++
		cc.mutex.Unlock()

		time.Sleep(RequestLifetime)
	}
}
