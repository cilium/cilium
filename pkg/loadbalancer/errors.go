// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import "errors"

var (
	// ErrServiceNotFound occurs when a frontend is being upserted that refers to
	// a non-existing service.
	ErrServiceNotFound = errors.New("service not found")

	// ErrFrontendConflict occurs when a frontend is being upserted but it already
	// exists and is owned by a different service.
	ErrFrontendConflict = errors.New("frontend already owned by another service")
)
