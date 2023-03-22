// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	memdb "github.com/hashicorp/go-memdb"
)

// Common index schemas
var (
	UUIDIndex       = Index("id")
	UUIDIndexSchema = &memdb.IndexSchema{
		Name:         string(UUIDIndex),
		AllowMissing: false,
		Unique:       true,
		Indexer:      &memdb.UUIDFieldIndex{Field: "UUID"},
	}

	RevisionIndex       = Index("revision")
	RevisionIndexSchema = &memdb.IndexSchema{
		Name:         string(RevisionIndex),
		AllowMissing: false,
		Unique:       false,
		Indexer:      &memdb.UintFieldIndex{Field: "Revision"},
	}
)
