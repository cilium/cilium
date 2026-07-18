// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import "log/slog"

// NewTestRegistry returns a new MapRegistry for testing.
// DO NOT use in production code.
func NewTestRegistry(log *slog.Logger) (*MapRegistry, error) {
	return new(log)
}

// StartTest starts the MapRegistry for testing.
// DO NOT use in production code.
func (r *MapRegistry) StartTest() error {
	return r.start()
}
