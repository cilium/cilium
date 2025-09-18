// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package legacy

// DaemonInitialization can be used to depend on the legacy daemon initialization.
// This will make sure the Hive start hook of the "Daemon cell" runs before the start
// hook of any dependent cell. In detail, `newDaemon` has been called, but `startDaemon`
// is likely going to run in parallel with the start hook of the dependent cell.
type DaemonInitialization struct{}
