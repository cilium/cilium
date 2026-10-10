// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import "github.com/cilium/cilium/pkg/container/set"

// Generation is a position in the cache-wide mutation sequence. The cache
// allocates one for each real mutation, including reverts. Revision and
// TransactionID distinguish properties of a resource from snapshot/response
// boundaries, but all three types use this sequence, not separate counters.
// A snapshot/response boundary is a Generation because it can include several
// API transactions and reverts, rather than identify one named value or API call.
// Zero represents initial state or prior absence, not an allocated mutation.
type Generation uint64

// Revision identifies the current named value, including its absence. It
// advances on every semantic change or deletion, whether made by an API
// transaction or a revert, and never rolls back when restoring an older value.
type Revision struct {
	revision Generation
}

// TransactionID identifies the API transaction which originally inserted or
// deleted a value. Reverts restore this identity with the previous value while
// assigning a fresh Revision. Zero records prior absence, not an API deletion.
type TransactionID struct {
	transaction Generation
}

// Revision and TransactionID are comparable single-member structs with the same
// storage cost as Generation. Their distinct private field names prevent direct
// conversions between roles. Arithmetic and numeric literal assignment are not
// supported; check zero values with IsZero. External callers use the helpers
// below rather than unwrapping the roles. Within this package, comparisons use
// the private Generation members directly and rely on their shared source.
// The cache owns that source; the types distinguish roles, not which cache
// allocated a number.

// Revision gives a changed named value the generation reserved for its mutation.
func (generation Generation) Revision() Revision { return Revision{revision: generation} }

// TransactionID identifies an API transaction by its reserved generation.
// Revert generations do not identify new API transactions.
func (generation Generation) TransactionID() TransactionID {
	return TransactionID{transaction: generation}
}

// IsZero reports initial state or a satisfied scope requirement.
func (revision Revision) IsZero() bool { return revision.revision == 0 }

// IsZero reports prior absence, not an allocated API transaction.
func (transaction TransactionID) IsZero() bool { return transaction.transaction == 0 }

// InitialRevision is the revision originally assigned by this API transaction.
// This relies on revisions and transaction IDs coming from the same Generation
// source. A revert's current revision may be newer than this initial revision.
func (transaction TransactionID) InitialRevision() Revision {
	return Revision{revision: transaction.transaction}
}

// MaxRevision includes a named value's revision in a wait boundary. This relies
// on revisions and boundaries coming from the same Generation source.
func (generation Generation) MaxRevision(revision Revision) Generation {
	return max(generation, revision.revision)
}

// MaxTransaction includes a transaction in a response-rollback boundary. This
// relies on transaction IDs and boundaries coming from the same Generation source.
func (generation Generation) MaxTransaction(transaction TransactionID) Generation {
	return max(generation, transaction.transaction)
}

// inTransactions tests whether a completion boundary identifies an implicated
// API transaction. This relies on transaction IDs and boundaries coming from
// the same Generation source. It is used only when propagating a NACK; comparing
// each transaction keeps the cross-type comparison explicit rather than treating
// an arbitrary response or revert boundary as an API transaction ID.
func (generation Generation) inTransactions(transactions set.Set[TransactionID]) bool {
	for transaction := range transactions.Members() {
		if transaction.transaction == generation {
			return true
		}
	}
	return false
}
