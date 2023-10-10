// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"github.com/cilium/cilium/pkg/time"
)

// BackoffDuration wraps Duration.
type BackoffDuration interface {
	// Duration returns a duration that depends on the given attempt count.
	Duration(attempt int) time.Duration
}
