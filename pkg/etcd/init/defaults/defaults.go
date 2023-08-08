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
	// RootRoleName is the name used by the "root" role that we create in etcd
	RootRoleName = "root"
	// RootUserName is the name used by the "root" user that we create in etcd
	RootUserName = "root"
	// ExternalWorkloadRoleName is the name used by the "external workload" role that we create in etcd
	ExternalWorkloadRoleName = "externalworkload"
	// ExternalWorkloadUserName is the name used by the "external workload" user that we create in etcd
	ExternalWorkloadUserName = "externalworkload"
	// AdminUsernamePrefix is a sprintf format string to assemble the admin username
	AdminUsernamePrefix = "admin-%s"
	// RemoteRoleName is the name used by the "external workload" role that we create in etcd
	RemoteRoleName = "remote"
	// RemoteUserName is the name used by the "external workload" user that we create in etcd
	RemoteUserName = "Remote"
)
