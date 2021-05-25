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

package endpointmanager

import "github.com/cilium/cilium/pkg/endpoint"

// Subscribers may register via Subscribe() to be notified when events occur.
type Subscriber interface {
	// EndpointCreated is called at the end of endpoint creation.
	// Implementations must not attempt write operations on the
	// EndpointManager from this callback.
	EndpointCreated(ep *endpoint.Endpoint)

	// EndpointDeleted is called at the end of endpoint deletion.
	// Implementations must not attempt write operations on the
	// EndpointManager from this callback.
	EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig)
}

func (mgr *EndpointManager) Subscribe(s Subscriber) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	mgr.subscribers[s] = struct{}{}
}

func (mgr *EndpointManager) Unsubscribe(s Subscriber) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	delete(mgr.subscribers, s)
}
