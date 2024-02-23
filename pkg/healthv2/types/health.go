// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// Health is the new health reporting interface to be used, this is mirroring
// github.com/cilium/hive/cells.(Health) temporarily.
// TODO: Remove this in favor of github.com/cilium/hive/cells.(Health) once it is ready.
type Health interface {
	OK(status string)
	Stopped(reason string)
	Degraded(reason string, err error)
	NewScope(name string) Health
	Close()
}
