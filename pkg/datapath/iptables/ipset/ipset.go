// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

const (
	CiliumNodeIPSetV4 = "cilium_node_set_v4"
	CiliumNodeIPSetV6 = "cilium_node_set_v6"
)

type Family string

const (
	INetFamily  Family = "inet"
	INet6Family Family = "inet6"
)

// Manager handles the kernel IP sets configuration
type Manager interface {
	AddToIPSet(name string, family Family, addrs ...netip.Addr)
	RemoveFromIPSet(name string, addrs ...netip.Addr)
}

type manager struct {
	logger  logrus.FieldLogger
	enabled bool

	db    *statedb.DB
	table statedb.RWTable[*tables.IPSet]

	ipset *ipset
}

// AddToIPSet adds the addresses to the ipset with given name and family.
// It creates the ipset if it doesn't already exist and doesn't error out
// if either the ipset or the IP already exist.
func (m *manager) AddToIPSet(name string, family Family, addrs ...netip.Addr) {
	if !m.enabled || len(addrs) == 0 {
		return
	}

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	var (
		obj   *tables.IPSet
		found bool
	)

	obj, _, found = m.table.First(txn, tables.IPSetNameIndex.Query(name))
	if !found {
		obj = &tables.IPSet{
			Name:   name,
			Family: string(family),
			Addrs:  tables.NewAddrSet(addrs...),
			Status: reconciler.StatusPending(),
		}
	} else {
		obj = obj.WithAddrs(addrs...) // clone object to avoid mutating the one returned by First
		obj.Status = reconciler.StatusPending()
	}
	_, _, _ = m.table.Insert(txn, obj)
	txn.Commit()
}

// RemoveFromBodeIPSet removes the addresses from the specified ipset.
func (m *manager) RemoveFromIPSet(name string, addrs ...netip.Addr) {
	if !m.enabled || len(addrs) == 0 {
		return
	}

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	obj, _, found := m.table.First(txn, tables.IPSetNameIndex.Query(name))
	if !found {
		return
	}
	obj = obj.WithoutAddrs(addrs...) // clone object to avoid mutating the one returned by First
	obj.Status = reconciler.StatusPending()
	_, _, _ = m.table.Insert(txn, obj)
	txn.Commit()
}

func newIPSetManager(
	lc cell.Lifecycle,
	logger logrus.FieldLogger,
	db *statedb.DB,
	table statedb.RWTable[*tables.IPSet],
	cfg config,
	ipset *ipset,
	_ reconciler.Reconciler[*tables.IPSet], // needed to enforce the correct hive ordering
) Manager {
	db.RegisterTable(table)
	mgr := &manager{
		logger:  logger,
		enabled: cfg.NodeIPSetNeeded,
		db:      db,
		table:   table,
		ipset:   ipset,
	}

	lc.Append(cell.Hook{OnStart: mgr.onStart})

	return mgr
}

func (m *manager) onStart(ctx cell.HookContext) error {
	if !m.enabled {
		// If node ipsets are not needed, clear the Cilium managed ones to remove possible stale entries.
		for _, ciliumNodeIPSet := range []string{CiliumNodeIPSetV4, CiliumNodeIPSetV6} {
			if err := m.ipset.remove(ctx, ciliumNodeIPSet); err != nil {
				m.logger.WithError(err).Infof("Unable to remove stale ipset %s. This is usually due to a stale iptables rule referring to it. "+
					"The set will not be removed. This is harmless and it will be removed at the next Cilium restart, when the stale iptables rule has been removed.", ciliumNodeIPSet)
			}
		}
		return nil
	}

	// When NodeIPSetNeeded is set, node ipsets must be created even if empty,
	// to avoid failures when referencing them in iptables masquerading rules.

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	if _, _, found := m.table.First(txn, tables.IPSetNameIndex.Query(CiliumNodeIPSetV4)); !found {
		if _, _, err := m.table.Insert(txn, &tables.IPSet{
			Name:   CiliumNodeIPSetV4,
			Family: string(INetFamily),
			Addrs:  tables.NewAddrSet(),
			Status: reconciler.StatusPending(),
		}); err != nil {
			return fmt.Errorf("error while inserting ipset %s entry in stateDB table", CiliumNodeIPSetV4)
		}
	}
	if _, _, found := m.table.First(txn, tables.IPSetNameIndex.Query(CiliumNodeIPSetV6)); !found {
		if _, _, err := m.table.Insert(txn, &tables.IPSet{
			Name:   CiliumNodeIPSetV6,
			Family: string(INet6Family),
			Addrs:  tables.NewAddrSet(),
			Status: reconciler.StatusPending(),
		}); err != nil {
			return fmt.Errorf("error while inserting ipset %s entry in stateDB table", CiliumNodeIPSetV6)
		}
	}
	txn.Commit()

	return nil
}

type ipset struct {
	executable

	log logrus.FieldLogger
}

func (i *ipset) create(ctx context.Context, name string, family string) error {
	if _, err := i.run(ctx, "create", name, "iphash", "family", family, "-exist"); err != nil {
		return fmt.Errorf("failed to create ipset %s: %w", name, err)
	}
	return nil
}

func (i *ipset) remove(ctx context.Context, name string) error {
	if _, err := i.run(ctx, "list", name); err != nil {
		// ipset does not exist, nothing to remove
		return nil
	}
	if _, err := i.run(ctx, "destroy", name); err != nil {
		return fmt.Errorf("failed to remove ipset %s: %w", name, err)
	}
	return nil
}

func (i *ipset) list(ctx context.Context, name string) (tables.AddrSet, error) {
	out, err := i.run(ctx, "list", name)
	if err != nil {
		return tables.AddrSet{}, fmt.Errorf("failed to list ipset %s: %w", name, err)
	}

	addrs := tables.NewAddrSet()
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		addrs = addrs.Insert(addr)
	}
	if err := scanner.Err(); err != nil {
		return tables.AddrSet{}, fmt.Errorf("failed to scan ipset %s: %w", name, err)
	}
	return addrs, nil
}

func (i *ipset) add(ctx context.Context, name string, addr netip.Addr) error {
	if _, err := i.run(ctx, "add", name, addr.String(), "-exist"); err != nil {
		return fmt.Errorf("failed to add %s to ipset %s: %w", addr, name, err)
	}
	return nil
}

func (i *ipset) del(ctx context.Context, name string, addr netip.Addr) error {
	if _, err := i.run(ctx, "del", name, addr.String(), "-exist"); err != nil {
		return fmt.Errorf("failed to del %s to ipset %s: %w", addr, name, err)
	}
	return nil
}

func (i *ipset) run(ctx context.Context, args ...string) ([]byte, error) {
	i.log.Debugf("Running command %s", i.fullCommand(args...))
	return i.exec(ctx, "ipset", args...)
}

func (i *ipset) fullCommand(args ...string) string {
	return strings.Join(append([]string{"ipset"}, args...), " ")
}

// useful to ease the creation of a mock ipset command for testing purposes
type executable interface {
	exec(ctx context.Context, name string, arg ...string) ([]byte, error)
}

type funcExecutable func(ctx context.Context, name string, arg ...string) ([]byte, error)

func (f funcExecutable) exec(ctx context.Context, name string, arg ...string) ([]byte, error) {
	return f(ctx, name, arg...)
}
