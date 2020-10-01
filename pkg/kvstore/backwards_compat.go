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

import "context"

const (
	// OperationalPath is the base path to store the operational details in the kvstore.
	OperationalPath = "cilium-net/operational"

	// servicePathV1 is the base path for the services stored in the kvstore.
	servicePathV1 = OperationalPath + "/Services/"
)

// deleteLegacyPrefixes removes old kvstore prefixes of non-persistent keys
// which have been used in the past but have been obsoleted since. We remove
// them on agent start to ensure that as users upgrade, we do not leave behind
// stale keys
//
// Rules:
//  - For non-persistent state, obsoletd prefixes can be deleted as soon as the
//    prefix has been declared obsolete
//
//  - For persistent configuration stored in the kvstore, a forward upgrade
//    path must be created which automatically removes the old keys on successful
//    translation.
//
func deleteLegacyPrefixes(ctx context.Context) {
	// Delete all keys in old services prefix
	Client().DeletePrefix(ctx, servicePathV1)
}
