// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import "slices"

// Revertible represents a successful operation whose final outcome depends on
// a larger transaction. The caller must eventually either finalize or revert
// it.
type Revertible interface {
	Revert() error
	Finalize()
}

// Revert makes a RevertFunc a revert-only Revertible.
func (f RevertFunc) Revert() error {
	return f()
}

// Finalize is a no-op for a revert-only Revertible.
func (RevertFunc) Finalize() {}

type finalizeRevertible func()

func (finalizeRevertible) Revert() error {
	return nil
}

func (f finalizeRevertible) Finalize() {
	f()
}

// Revertibles records revertibles in transaction order. Successful
// transactions are finalized in forward order, while failed transactions are
// reverted in reverse order.
type Revertibles struct {
	items []Revertible
}

// Empty reports whether there are no revertibles.
func (revertibles *Revertibles) Empty() bool {
	return len(revertibles.items) == 0
}

// Add appends a revertible. A nil revertible is ignored.
func (revertibles *Revertibles) Add(revertible Revertible) {
	if revertible != nil {
		revertibles.items = append(revertibles.items, revertible)
	}
}

// AddRevert appends a revert-only function.
func (revertibles *Revertibles) AddRevert(revertFunc RevertFunc) {
	if revertFunc != nil {
		revertibles.Add(revertFunc)
	}
}

// AddFinalize appends a finalize-only function.
func (revertibles *Revertibles) AddFinalize(finalize func()) {
	if finalize != nil {
		revertibles.Add(finalizeRevertible(finalize))
	}
}

// Finalize finalizes all revertibles in forward order.
func (revertibles *Revertibles) Finalize() {
	for _, revertible := range revertibles.items {
		revertible.Finalize()
	}
}

// Revert reverts all revertibles in reverse order. It returns the first error
// and skips any remaining revertibles, matching RevertStack's behavior.
func (revertibles *Revertibles) Revert() error {
	for _, revertible := range slices.Backward(revertibles.items) {
		if err := revertible.Revert(); err != nil {
			return err
		}
	}
	return nil
}
