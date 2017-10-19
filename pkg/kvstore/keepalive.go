// Copyright 2016-2017 Authors of Cilium
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

package kvstore

import (
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	// LeaseTTL is the time-to-live ofthe lease
	LeaseTTL = 15 * time.Minute // 15 minutes

	// KeepAliveInterval is the interval in which the lease is being
	// renewed. This must be set to a value lesser than the LeaseTTL
	KeepAliveInterval = 5 * time.Minute

	// RetryInterval is the interval in which retries occur in the case of
	// errors in communication with the KVstore. THis should be set to a
	// small value to account for temporary errors while communicating with
	// the KVstore.
	RetryInterval = 1 * time.Minute
)

// CreateLease creates a new lease with the given ttl
func CreateLease(ttl time.Duration) (interface{}, error) {
	lease, err := Client().CreateLease(ttl)
	trace("CreateLease", err, log.Fields{fieldTTL: ttl, fieldLease: lease})
	return lease, err
}

// KeepAlive keeps a lease created with CreateLease alive
func KeepAlive(lease interface{}) error {
	err := Client().KeepAlive(lease)
	trace("KeepAlive", err, log.Fields{fieldLease: lease})
	return err
}

func startKeepalive() {
	go func() {
		sleepTime := KeepAliveInterval
		for {
			if err := KeepAlive(leaseInstance); err != nil {
				log.WithError(err).Warn("Unable to keep lease alive")
				sleepTime = RetryInterval
			}
			time.Sleep(sleepTime)
		}
	}()
}
