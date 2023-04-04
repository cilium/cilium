// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

// ByID queries by the "ID" field. The type of "ID" is table specific, thus
// this function takes an 'any'.
func ByID(id any) Query {
	return Query{Index("id"), []any{id}}
}

// ByUUID queries the table by UUID.
func ByUUID(uuid UUID) Query {
	return Query{UUIDIndex, []any{uuid}}
}

// ByRevision queries the table by revision. The target table must include
// the RevisionIndexSchema.
func ByRevision(rev uint64) Query {
	return Query{RevisionIndex, []any{rev}}
}

// All is a query that returns all objects. Order is based on the "id"
// field index.
var All = Query{"id", []any{}}
