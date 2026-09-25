// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"time"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

const EndpointFQDNStateTableName = "fqdn-endpoint-state"

type EndpointFQDNTableKey struct {
	EndpointID uint16
	Name       string
	IP         netip.Addr
}

// EndpointFQDNIPKey selects DNS names observed by one endpoint for one IP.
type EndpointFQDNIPKey struct {
	EndpointID uint16
	IP         netip.Addr
}

type EndpointFQDNMapping struct {
	EndpointID     uint16
	Name           string
	IP             netip.Addr
	LookupTime     time.Time
	TTL            uint32
	ExpirationTime time.Time
}

func (m EndpointFQDNMapping) TableHeader() []string {
	return []string{"EndpointID", "Name", "IP", "LookupTime", "TTL", "ExpirationTime"}
}

func (m EndpointFQDNMapping) TableRow() []string {
	return []string{
		strconv.FormatUint(uint64(m.EndpointID), 10),
		m.Name,
		m.IP.String(),
		m.LookupTime.Format(time.RFC3339Nano),
		strconv.FormatUint(uint64(m.TTL), 10),
		m.ExpirationTime.Format(time.RFC3339Nano),
	}
}

var _ statedb.TableWritable = EndpointFQDNMapping{}

func endpointFQDNKey(endpointID uint16, name string, ip netip.Addr) index.Key {
	ipBytes := ip.Unmap().As16()
	key := make([]byte, 2+len(name)+1+len(ipBytes))
	binary.BigEndian.PutUint16(key, endpointID)
	copy(key[2:], name)
	key[2+len(name)] = 0
	copy(key[3+len(name):], ipBytes[:])
	return key
}

func endpointFQDNIPKey(endpointID uint16, ip netip.Addr) index.Key {
	key := make(index.Key, 2+16)
	binary.BigEndian.PutUint16(key, endpointID)
	ipBytes := ip.Unmap().As16()
	copy(key[2:], ipBytes[:])
	return key
}

var (
	endpointFQDNPrimaryIndex = statedb.Index[EndpointFQDNMapping, EndpointFQDNTableKey]{
		Name: "key",
		FromObject: func(m EndpointFQDNMapping) index.KeySet {
			return index.NewKeySet(endpointFQDNKey(m.EndpointID, m.Name, m.IP))
		},
		FromKey: func(key EndpointFQDNTableKey) index.Key {
			return endpointFQDNKey(key.EndpointID, key.Name, key.IP)
		},
		Unique: true,
	}
	endpointFQDNEndpointIndex = statedb.Index[EndpointFQDNMapping, uint16]{
		Name: "endpoint",
		FromObject: func(m EndpointFQDNMapping) index.KeySet {
			return index.NewKeySet(index.Uint16(m.EndpointID))
		},
		FromKey:    index.Uint16,
		FromString: index.Uint16String,
		Unique:     false,
	}
	endpointFQDNNameIndex = statedb.Index[EndpointFQDNMapping, string]{
		Name: "name",
		FromObject: func(m EndpointFQDNMapping) index.KeySet {
			return index.NewKeySet(index.String(m.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}
	endpointFQDNIPIndex = statedb.Index[EndpointFQDNMapping, netip.Addr]{
		Name: "ip",
		FromObject: func(m EndpointFQDNMapping) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(m.IP.Unmap()))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
		Unique:     false,
	}
	endpointFQDNEndpointIPIndex = statedb.Index[EndpointFQDNMapping, EndpointFQDNIPKey]{
		Name: "endpoint-ip",
		FromObject: func(m EndpointFQDNMapping) index.KeySet {
			return index.NewKeySet(endpointFQDNIPKey(m.EndpointID, m.IP))
		},
		FromKey: func(key EndpointFQDNIPKey) index.Key {
			return endpointFQDNIPKey(key.EndpointID, key.IP)
		},
		Unique: false,
	}
)

var (
	QueryEndpointFQDNByEndpoint   = endpointFQDNEndpointIndex.Query
	QueryEndpointFQDNByName       = endpointFQDNNameIndex.Query
	QueryEndpointFQDNByIP         = endpointFQDNIPIndex.Query
	QueryEndpointFQDNByEndpointIP = endpointFQDNEndpointIPIndex.Query
)

func NewEndpointFQDNStateTable(db *statedb.DB) (statedb.RWTable[EndpointFQDNMapping], error) {
	return statedb.NewTable(
		db,
		EndpointFQDNStateTableName,
		endpointFQDNPrimaryIndex,
		endpointFQDNEndpointIndex,
		endpointFQDNNameIndex,
		endpointFQDNIPIndex,
		endpointFQDNEndpointIPIndex,
	)
}

func MustNewEndpointFQDNStateTable(db *statedb.DB) statedb.RWTable[EndpointFQDNMapping] {
	table, err := NewEndpointFQDNStateTable(db)
	if err != nil {
		panic(err)
	}
	return table
}
