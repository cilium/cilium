// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstore")

const (
	// fieldKVStoreModule is the name of the kvstore backend (etcd or consul)
	fieldKVStoreModule = "module"

	// name of watcher
	fieldWatcher = "watcher"

	// key revision
	fieldRev = "revision"

	// fieldSession refers to a connection/session with the kvstore
	fieldSession = "session"

	// fieldPrefix is the prefix of the key used in the operation
	fieldPrefix = "prefix"

	// fieldKey is the prefix of the key used in the operation
	fieldKey = "key"

	// fieldValue is the prefix of the key used in the operation
	fieldValue = "value"

	// fieldCondition is the condition that requires to be met
	fieldCondition = "condition"

	// fieldNumEntries is the number of entries in the result
	fieldNumEntries = "numEntries"

	// fieldRemainingEntries is the number of entries still to be retrieved
	fieldRemainingEntries = "remainingEntries"

	// fieldAttachLease is true if the key must be attached to a lease
	fieldAttachLease = "attachLease"

	// fieldEtcdEndpoint is the etcd endpoint we talk to
	fieldEtcdEndpoint = "etcdEndpoint"

	// FieldUser identifies a user in the kvstore
	FieldUser = logfields.User

	// FieldRole identifies a role in the kvstore
	FieldRole = "role"
)
