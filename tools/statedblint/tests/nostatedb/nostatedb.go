// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package nostatedb tests that we don't falsely fail mutation check
// on non-statedb code.
// nolint:all // ignore all lints on purpose
package nostatedb

type widget struct {
	value int
}

func mutate(w *widget) {
	w.value++
}
