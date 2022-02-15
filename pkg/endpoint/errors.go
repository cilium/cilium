// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import "errors"

var (
	// ErrNotAlive is an error which indicates that the endpoint should not be
	// rlocked because it is currently being removed.
	ErrNotAlive = errors.New("rlock failed: endpoint is in the process of being removed")
)
