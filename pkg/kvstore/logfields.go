// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// key revision
	fieldRev = "revision"

	// fieldPrefix is the prefix of the key used in the operation
	fieldPrefix = "prefix"

	// fieldKey is the prefix of the key used in the operation
	fieldKey = "key"

	// fieldValue is the prefix of the key used in the operation
	fieldValue = "value"

	// fieldNumEntries is the number of entries in the result
	fieldNumEntries = "numEntries"

	// fieldRemainingEntries is the number of entries still to be retrieved
	fieldRemainingEntries = "remainingEntries"

	// fieldAttachLease is true if the key must be attached to a lease
	fieldAttachLease = "attachLease"

	// FieldUser identifies a user in the kvstore
	FieldUser = logfields.User

	// FieldRole identifies a role in the kvstore
	FieldRole = "role"

	fieldRecreated = "recreated"

	fieldSuccess = "success"
)
