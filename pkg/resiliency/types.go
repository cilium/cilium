// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

// Category tracks error type resiliency classification.
type Category int

const (
	// ResUnavailable tracks external manipulation (manual or accidental)
	ResUnavailable Category = iota

	// ResExt tracks unavailability of external resource (malicious or accidental)
	ResExt

	// ResLimit tracks constraint on resources or API
	ResLimit

	// ResDpath tracks datapath misbehavior
	ResDpath

	// ResCplane tracks control plane misbehavior
	ResCplane

	// ExtSys track failure of system interactions
	ExtSys
)

// Retryer represents class of errors that could be retried.
type Retryer interface {

	// Retryable checks if error is retryable or not.
	Retryable() bool
}
