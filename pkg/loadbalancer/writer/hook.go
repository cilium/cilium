// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ServiceHook is a function invoked when a frontend has been updated. A hook
// can manipulate the frontend before the changes are seen by other components.
//
// The main use-case for a hook is to set e.g. L7 proxy port before the frontend
// is reconciled and thus avoid unnecessary work.
//
// For consistency the hook should only access StateDB tables via the provided
// read transaction.
type ServiceHook = func(txn statedb.ReadTxn, svc *loadbalancer.Service)
