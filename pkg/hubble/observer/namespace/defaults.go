// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package namespace

import "time"

const (
	// cleanupInterval is the interval at which the namespace list from the
	// manager is garbage collected.
	cleanupInterval = 5 * time.Minute
	// namespaceTTL is the time after which a namespace is garbage collected.
	namespaceTTL = 1 * time.Hour
)
