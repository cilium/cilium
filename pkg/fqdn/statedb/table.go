// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"net/netip"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	statedb "github.com/cilium/statedb"
)

const TableName = fqdn.FQDNStateTableName

type FQDNMapping = fqdn.FQDNMapping
type FQDNTableKey = fqdn.FQDNTableKey

var (
	PrimaryIndex = fqdn.FQDNStatePrimaryIndex
	NameIndex    = fqdn.FQDNNameIndex
	IPIndex      = fqdn.FQDNIPIndex
	Expiration   = fqdn.FQDNExpirationIndex
)

func NewTable(db *statedb.DB) (statedb.RWTable[FQDNMapping], error) {
	return fqdn.NewFQDNStateTable(db)
}

func MustNewTable(db *statedb.DB) statedb.RWTable[FQDNMapping] {
	return fqdn.MustNewFQDNStateTable(db)
}

func ParseKey(s string) (FQDNTableKey, error) {
	return fqdn.ParseFQDNTableKey(s)
}

func Persist(db *statedb.DB, table statedb.Table[FQDNMapping], path string) error {
	return fqdn.PersistFQDNState(db, table, path)
}

func Restore(txn statedb.WriteTxn, table statedb.RWTable[FQDNMapping], path string) error {
	return fqdn.RestoreFQDNState(txn, table, path)
}

func QueryByName(name string) statedb.Query[FQDNMapping] {
	return NameIndex.Query(name)
}

func QueryByIP(ip netip.Addr) statedb.Query[FQDNMapping] {
	return IPIndex.Query(ip)
}

func QueryByExpiration(ts time.Time) statedb.Query[FQDNMapping] {
	return Expiration.Query(ts)
}
