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

	IDIndex = Index("id")

	RevisionIndex       = Index("revision")
	RevisionIndexSchema = &memdb.IndexSchema{
		Name:         string(RevisionIndex),
		AllowMissing: false,
		Unique:       false,
		Indexer:      &memdb.UintFieldIndex{Field: "Revision"},
	}

	IPIndex  = Index("ip")
	IPSchema = &memdb.IndexSchema{
		Name:         string(IPIndex),
		AllowMissing: false,
		Unique:       false,
		Indexer:      &IPFieldIndex{Field: "IP"},
	}
)
