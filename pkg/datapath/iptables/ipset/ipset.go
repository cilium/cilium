// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

type AddrSet = sets.Set[netip.Addr]

// Manager handles the kernel IP sets configuration
type Manager interface {
	NewInitializer() Initializer
	AddToIPSet(name string, family Family, addrs ...netip.Addr)
	RemoveFromIPSet(name string, addrs ...netip.Addr)
}

type Initializer interface {
	InitDone()
}

type initializer struct {
	done lock.DoneFunc
}

func (i *initializer) InitDone() {
	// lock.DoneFunc's are wrapped in sync.Once, so it is safe to call this
	// multiple times.
	i.done()
}

type manager struct {
	logger  *slog.Logger
	enabled bool

	db    *statedb.DB
	table statedb.RWTable[*tables.IPSetEntry]

	ipset *ipset

	reconciler reconciler.Reconciler[*tables.IPSetEntry]
	ops        *ops

	started   atomic.Bool
	startedWG *lock.StoppableWaitGroup
}

func (m *manager) NewInitializer() Initializer {
	if m.started.Load() {
		panic("an initializer to the ipset manager cannot be taken after the manager started")
	}
	return &initializer{done: m.startedWG.Add()}
}

// AddToIPSet adds the addresses to the ipset with given name and family.
// It creates the ipset if it doesn't already exist and doesn't error out
// if either the ipset or the IP already exist.
func (m *manager) AddToIPSet(name string, family Family, addrs ...netip.Addr) {
	if !m.enabled {
		return
	}

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	for _, addr := range addrs {
		key := tables.IPSetEntryKey{
			Name: name,
			Addr: addr,
		}
		if _, _, found := m.table.Get(txn, tables.IPSetEntryIndex.Query(key)); found {
			continue
		}
		_, _, _ = m.table.Insert(txn, &tables.IPSetEntry{
			Name:   name,
			Family: string(family),
			Addr:   addr,
			Status: reconciler.StatusPending(),
		})
	}

	txn.Commit()
}

// RemoveFromIPSet removes the addresses from the specified ipset.
func (m *manager) RemoveFromIPSet(name string, addrs ...netip.Addr) {
	if !m.enabled {
		return
	}

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	for _, addr := range addrs {
		key := tables.IPSetEntryKey{
			Name: name,
			Addr: addr,
		}
		obj, _, found := m.table.Get(txn, tables.IPSetEntryIndex.Query(key))
		if !found {
			continue
		}
		m.table.Delete(txn, obj)
	}

	txn.Commit()
}

func newIPSetManager(
	logger *slog.Logger,
	lc cell.Lifecycle,
	jg job.Group,
	health cell.Health,
	db *statedb.DB,
	table statedb.RWTable[*tables.IPSetEntry],
	cfg config,
	ipset *ipset,
	reconciler reconciler.Reconciler[*tables.IPSetEntry],
	ops *ops,
) Manager {
	mgr := &manager{
		logger:     logger,
		enabled:    cfg.NodeIPSetNeeded,
		db:         db,
		table:      table,
		ipset:      ipset,
		reconciler: reconciler,
		ops:        ops,
		startedWG:  lock.NewStoppableWaitGroup(),
	}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if !cfg.NodeIPSetNeeded {
				return nil
			}

			// When NodeIPSetNeeded is set, node ipsets must be created even if empty,
			// to avoid failures when referencing them in iptables masquerading rules.
			if err := ipset.create(ctx, CiliumNodeIPSetV4, string(INetFamily)); err != nil {
				return fmt.Errorf("error while creating ipset %s", CiliumNodeIPSetV4)
			}
			if err := ipset.create(ctx, CiliumNodeIPSetV6, string(INet6Family)); err != nil {
				return fmt.Errorf("error while creating ipset %s", CiliumNodeIPSetV6)
			}
			return nil
		},
	})

	jg.Add(job.OneShot("ipset-init-finalizer", mgr.init))

	return mgr
}

func (m *manager) init(ctx context.Context, _ cell.Health) error {
	if !m.enabled {
		// If node ipsets are not needed, clear the Cilium managed ones to remove possible stale entries.
		for _, ciliumNodeIPSet := range []string{CiliumNodeIPSetV4, CiliumNodeIPSetV6} {
			if err := m.ipset.remove(ctx, ciliumNodeIPSet); err != nil {
				m.logger.Info("Unable to remove stale ipset. This is usually due to a stale iptables rule referring to it. "+
					"The set will not be removed. This is harmless and it will be removed at the next Cilium restart, when the stale iptables rule has been removed.",
					logfields.IPSet, ciliumNodeIPSet,
					logfields.Error, err)
			}
		}
		return nil
	}

	// no further initializers after manager started
	m.started.Store(true)
	m.startedWG.Stop()

	// wait for all existing initializers to complete before finalizing manager
	// initialization and allowing prune operations in the ipset reconciler
	select {
	case <-ctx.Done():
		return nil
	case <-m.startedWG.WaitChannel():
	}

	m.ops.enablePrune()
	m.reconciler.Prune()

	return nil
}

type ipset struct {
	log *slog.Logger

	executable
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

func (i *ipset) list(ctx context.Context, name string) (AddrSet, error) {
	out, err := i.run(ctx, "list", name)
	if err != nil {
		return AddrSet{}, fmt.Errorf("failed to list ipset %s: %w", name, err)
	}

	addrs := AddrSet{}
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
		return AddrSet{}, fmt.Errorf("failed to scan ipset %s: %w", name, err)
	}
	return addrs, nil
}

func (i *ipset) addBatch(ctx context.Context, batch map[string][]netip.Addr) error {
	b := strings.Builder{}
	for name, addrs := range batch {
		for _, addr := range addrs {
			fmt.Fprintf(&b, "add %s %s -exist\n", name, addr)
		}
	}
	_, err := i.exec(ctx, "ipset", b.String(), "restore")
	return err
}

func (i *ipset) delBatch(ctx context.Context, batch map[string][]netip.Addr) error {
	b := strings.Builder{}
	for name, addrs := range batch {
		for _, addr := range addrs {
			fmt.Fprintf(&b, "del %s %s -exist\n", name, addr)
		}
	}
	_, err := i.exec(ctx, "ipset", b.String(), "restore")
	return err
}

func (i *ipset) run(ctx context.Context, args ...string) ([]byte, error) {
	i.log.Debug("Running command",
		logfields.Cmd, i.fullCommand(args...),
	)
	return i.exec(ctx, "ipset", "", args...)
}

func (i *ipset) fullCommand(args ...string) string {
	return strings.Join(append([]string{"ipset"}, args...), " ")
}

// useful to ease the creation of a mock ipset command for testing purposes
type executable interface {
	exec(ctx context.Context, name string, stdin string, arg ...string) ([]byte, error)
}

type funcExecutable func(ctx context.Context, name string, stdin string, arg ...string) ([]byte, error)

func (f funcExecutable) exec(ctx context.Context, name string, stdin string, arg ...string) ([]byte, error) {
	return f(ctx, name, stdin, arg...)
}
