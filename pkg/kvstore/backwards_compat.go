// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
//
//   - For non-persistent state, obsoletd prefixes can be deleted as soon as the
//     prefix has been declared obsolete
//   - For persistent configuration stored in the kvstore, a forward upgrade
//     path must be created which automatically removes the old keys on successful
//     translation.
func deleteLegacyPrefixes(ctx context.Context) {
	// Delete all keys in old services prefix
	Client().DeletePrefix(ctx, servicePathV1)
}
