// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

const FQDNStateTableName = "fqdn-state"

// FQDNTableKey identifies a specific DNS mapping for a name and IP pair.
type FQDNTableKey struct {
	Name string
	IP   netip.Addr
}

// FQDNMapping stores the canonical global DNS state that is represented in
// StateDB. Each row is keyed by a single (name, IP) mapping, which preserves the
// per-IP expiration semantics used by DNSCache.
type FQDNMapping struct {
	Name string
	IP   netip.Addr

	LookupTime     time.Time
	TTL            uint32
	ExpirationTime time.Time
}

func (m FQDNMapping) Key() FQDNTableKey {
	return FQDNTableKey{Name: m.Name, IP: m.IP.Unmap()}
}

func (m FQDNMapping) TableHeader() []string {
	return []string{"Name", "IP", "LookupTime", "TTL", "ExpirationTime"}
}

func (m FQDNMapping) TableRow() []string {
	return []string{
		m.Name,
		m.IP.String(),
		m.LookupTime.Format(time.RFC3339Nano),
		strconv.FormatUint(uint64(m.TTL), 10),
		m.ExpirationTime.Format(time.RFC3339Nano),
	}
}

var _ statedb.TableWritable = FQDNMapping{}

func encodeFQDNStateKey(name string, ip netip.Addr) index.Key {
	ip = ip.Unmap()
	key := append([]byte(name), 0)
	if !ip.IsValid() {
		return key
	}
	ipBytes := ip.As16()
	return append(key, ipBytes[:]...)
}

func parseFQDNStateKey(key index.Key) (FQDNTableKey, error) {
	if len(key) == 0 {
		return FQDNTableKey{}, fmt.Errorf("empty fqdn key")
	}
	nameEnd := bytes.IndexByte(key, 0)
	if nameEnd < 0 {
		return FQDNTableKey{}, fmt.Errorf("fqdn key missing name separator")
	}
	name := string(key[:nameEnd])
	if len(key[nameEnd+1:]) != 16 {
		return FQDNTableKey{}, fmt.Errorf("fqdn key has invalid IP length: %d", len(key[nameEnd+1:]))
	}
	var ipBytes [16]byte
	copy(ipBytes[:], key[nameEnd+1:])
	return FQDNTableKey{Name: name, IP: netip.AddrFrom16(ipBytes)}, nil
}

func (k FQDNTableKey) String() string {
	return k.Name + "|" + k.IP.String()
}

func ParseFQDNTableKey(s string) (FQDNTableKey, error) {
	name, ipString, ok := strings.Cut(s, "|")
	if !ok {
		return FQDNTableKey{}, fmt.Errorf("invalid fqdn key %q", s)
	}
	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		return FQDNTableKey{}, err
	}
	return FQDNTableKey{Name: name, IP: ip}, nil
}

var (
	FQDNStatePrimaryIndex = statedb.Index[FQDNMapping, FQDNTableKey]{
		Name: "key",
		FromObject: func(m FQDNMapping) index.KeySet {
			return index.NewKeySet(encodeFQDNStateKey(m.Name, m.IP))
		},
		FromKey: func(key FQDNTableKey) index.Key {
			return encodeFQDNStateKey(key.Name, key.IP)
		},
		FromString: func(s string) (index.Key, error) {
			key, err := ParseFQDNTableKey(s)
			if err != nil {
				return nil, err
			}
			return encodeFQDNStateKey(key.Name, key.IP), nil
		},
		Unique: true,
	}

	FQDNNameIndex = statedb.Index[FQDNMapping, string]{
		Name: "name",
		FromObject: func(m FQDNMapping) index.KeySet {
			return index.NewKeySet(index.String(m.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	FQDNIPIndex = statedb.Index[FQDNMapping, netip.Addr]{
		Name: "ip",
		FromObject: func(m FQDNMapping) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(m.IP.Unmap()))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
		Unique:     false,
	}

	FQDNExpirationIndex = statedb.Index[FQDNMapping, time.Time]{
		Name: "expiration",
		FromObject: func(m FQDNMapping) index.KeySet {
			return index.NewKeySet(index.Uint64(uint64(m.ExpirationTime.UnixNano())))
		},
		FromKey: func(ts time.Time) index.Key {
			return index.Uint64(uint64(ts.UnixNano()))
		},
		FromString: func(s string) (index.Key, error) {
			ts, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return nil, err
			}
			return index.Uint64(uint64(ts.UnixNano())), nil
		},
		Unique: false,
	}
)

func NewFQDNStateTable(db *statedb.DB) (statedb.RWTable[FQDNMapping], error) {
	return statedb.NewTable(
		db,
		FQDNStateTableName,
		FQDNStatePrimaryIndex,
		FQDNNameIndex,
		FQDNIPIndex,
		FQDNExpirationIndex,
	)
}

func MustNewFQDNStateTable(db *statedb.DB) statedb.RWTable[FQDNMapping] {
	tbl, err := NewFQDNStateTable(db)
	if err != nil {
		panic(err)
	}
	return tbl
}

// PersistFQDNState writes the current snapshot of the FQDN StateDB table as a
// single JSON object and atomically renames it into place.
func PersistFQDNState(db *statedb.DB, table statedb.Table[FQDNMapping], path string) error {
	if table == nil {
		return fmt.Errorf("missing fqdn state table")
	}
	if db == nil {
		return fmt.Errorf("missing statedb")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", path, err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temp file for %q: %w", path, err)
	}
	tmpPath := file.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if err := db.ReadTxn().WriteJSON(file, table.Name()); err != nil {
		_ = file.Close()
		return fmt.Errorf("write FQDN state snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp file for %q: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %q into place: %w", path, err)
	}
	return nil
}

// ReadFQDNStateFile decodes the JSON produced by PersistFQDNState into a list of
// FQDN mappings.
func ReadFQDNStateFile(path string) ([]FQDNMapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var snapshot map[string][]FQDNMapping
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("unmarshal fqdn state file: %w", err)
	}
	return snapshot[FQDNStateTableName], nil
}

// RestoreFQDNState loads a persisted FQDN table snapshot back into the table.
func RestoreFQDNState(txn statedb.WriteTxn, table statedb.RWTable[FQDNMapping], path string) error {
	rows, err := ReadFQDNStateFile(path)
	if err != nil {
		return err
	}
	for i, row := range rows {
		if row.Name == "" {
			return fmt.Errorf("invalid fqdn state row %d: empty name", i)
		}
		if !row.IP.IsValid() {
			return fmt.Errorf("invalid fqdn state row %d: invalid IP %q", i, row.IP)
		}
		if row.LookupTime.IsZero() {
			row.LookupTime = time.Now().UTC()
		}
		if row.ExpirationTime.IsZero() && row.TTL > 0 {
			row.ExpirationTime = row.LookupTime.Add(time.Duration(row.TTL) * time.Second)
		}
		if _, _, err := table.Insert(txn, row); err != nil {
			return fmt.Errorf("restore fqdn row %d: %w", i, err)
		}
	}
	return nil
}
