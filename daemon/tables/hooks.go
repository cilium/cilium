package tables

import "github.com/cilium/cilium/pkg/statedb"

// Hook is a function that runs when a service is upserted. It can perform reads using the provided
// ReadTxn, but for consistency it must not depend on any other data (except when the data is constant).
// The hook can modify the service object.
type Hook func(statedb.ReadTxn, *Service)
