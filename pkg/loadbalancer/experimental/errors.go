// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import "errors"

var (
	// ErrServiceNotFound occurs when a frontend is being upserted that refers to
	// a non-existing service.
	ErrServiceNotFound = errors.New("service not found")
)
