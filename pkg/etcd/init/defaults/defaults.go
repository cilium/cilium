// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"time"
)

const (
	// EtcdDataDirectory is the default data directory for etcd
	EtcdDataDirectory = "/var/run/etcd"
	// EtcdClusterName is the default cluster name
	EtcdClusterName = "clustermesh-apiserver"
	// IPv6 is the default IPv6 configuration
	IPv6 = false
	// StartupTimeout is the timeout that is used when establishing a new
	// connection.
	StartupTimeout = 30 * time.Second
	// GopsPort is the default port for gops to listen on.
	GopsPort = 9893
	// PprofAddress is the default port for pprof to listen on.
	PprofAddress = "localhost"
	// PprofPort is the default port for pprof to listen on.
	PprofPort = 6062
)
