// Copyright 2019 Authors of Cilium
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

package identitymanager

import (
	"github.com/cilium/cilium/pkg/identity"
)

// Observer can sign up to receive events whenever local identities are removed.
type Observer interface {
	// LocalEndpointIdentityAdded is called when an identity first becomes
	// used on the node. Implementations must ensure that the callback
	// returns within a reasonable period.
	LocalEndpointIdentityAdded(*identity.Identity)

	// LocalEndpointIdentityRemoved is called when an identity is no longer
	// in use on the node. Implementations must ensure that the callback
	// returns within a reasonable period.
	LocalEndpointIdentityRemoved(*identity.Identity)
}
