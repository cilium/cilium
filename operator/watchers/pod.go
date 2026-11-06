// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"k8s.io/client-go/tools/cache"
)

// PodStore has a minimal copy of all pods running in the cluster.
// Warning: The pods stored in the cache are not intended to be used for Update
// operations in k8s as some of its fields are not populated.
var PodStore cache.Store
