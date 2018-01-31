// Copyright 2016-2018 Authors of Cilium
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
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"

	"github.com/sirupsen/logrus"
)

var (
	// LeaseTTL is the time-to-live ofthe lease
	LeaseTTL = 15 * time.Minute // 15 minutes

	// KeepAliveInterval is the interval in which the lease is being
	// renewed. This must be set to a value lesser than the LeaseTTL
	KeepAliveInterval = 5 * time.Minute

	// RetryInterval is the interval in which retries occur in the case of
	// errors in communication with the KVstore. This should be set to a
	// small value to account for temporary errors while communicating with
	// the KVstore.
	RetryInterval = 1 * time.Minute
)

// CreateLease creates a new lease with the given ttl
func CreateLease(ttl time.Duration) (interface{}, error) {
	lease, err := Client().CreateLease(ttl)
	Trace("CreateLease", err, logrus.Fields{fieldTTL: ttl, fieldLease: lease})
	return lease, err
}

// KeepAlive keeps a lease created with CreateLease alive
func KeepAlive(lease interface{}) error {
	err := Client().KeepAlive(lease)
	Trace("KeepAlive", err, logrus.Fields{fieldLease: lease})
	return err
}

func renewDefaultLease() error {
	l, err := CreateLease(LeaseTTL)
	if err != nil {
		return fmt.Errorf("Unable to create lease: %s", err)
	}

	leaseMutex.Lock()
	if leaseInstance != nil {
		defaultClient.DeleteLease(leaseInstance)
	}
	leaseInstance = l
	leaseMutex.Unlock()

	// keep default lease alive
	kvstoreControllers.UpdateController("kvstore-lease-keepalive",
		controller.ControllerParams{
			DoFunc: func() error {
				leaseMutex.RLock()
				defer leaseMutex.RUnlock()

				return KeepAlive(leaseInstance)
			},
			RunInterval: KeepAliveInterval,
		},
	)

	return nil
}
