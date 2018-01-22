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
)

var (
	// defaultClient is the default client initialized by initClient
	defaultClient BackendOperations

	// leaseInstance is the backend specific lease object. The lease is
	// created by initClient()
	leaseInstance interface{}
)

func initClient(module backendModule) error {
	c, err := module.newClient()
	if err != nil {
		return err
	}

	log.Infof("Creating kvstore client for %s backend", module.getName())

	defaultClient = c

	deleteLegacyPrefixes()

	l, err := CreateLease(LeaseTTL)
	if err != nil {
		defaultClient = nil
		return fmt.Errorf("Unable to create lease: %s", err)
	}

	leaseInstance = l

	return nil
}

// Client returns the global kvstore client or nil if the client is not configured yet
func Client() BackendOperations {
	return defaultClient
}
