// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

// Level denotes what kind an update is.
type Level string

const (
	// StatusUnknown is the default status of a Module, prior to it reporting
	// any status.
	// All created
	StatusUnknown Level = "Unknown"

	// StatusStopped is the status of a Module that has completed, further updates
	// will not be processed.
	StatusStopped Level = "Stopped"

	// StatusDegraded is the status of a Module that has entered a degraded state.
	StatusDegraded Level = "Degraded"

	// StatusOK is the status of a Module that has achieved a desired state.
	StatusOK Level = "OK"
)

// Health provides a method of declaring a Modules health status.
//
// The interface is meant to be used with "ModuleDecorator" to inject it into
// the scope of modules.
//
// Implementation for health reporting is not included with the Hive library.
type Health interface {
	// OK declares that a Module has achieved a desired state and has not entered
	// any unexpected or incorrect states.
	// Modules should only declare themselves as 'OK' once they have stabilized,
	// rather than during their initial state. This should be left to be reported
	// as the default "unknown" to denote that the module has not reached a "ready"
	// health state.
	OK(status string)

	// Stopped reports that a module has completed, and will no longer report any
	// health status.
	// Implementations should differentiate that a stopped module may also be OK or Degraded.
	// Stopping a reporting should only affect future updates.
	Stopped(reason string)

	// Degraded declares that a module has entered a degraded state.
	// This means that it may have failed to provide it's intended services, or
	// to perform it's desired task.
	Degraded(reason string, err error)

	// NewScope constructs a new scoped health reporter.
	NewScope(name string) Health

	// Close closes this health scope and removes it. This is distinct from
	// 'Stopped' in that after closing the health status will disappear completely.
	Close()
}
