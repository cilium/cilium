// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/time"
)

type skiplbParams struct {
	cell.In

	Log                *slog.Logger
	IsEnabled          lrpIsEnabled
	DB                 *statedb.DB
	Lifecycle          cell.Lifecycle
	DesiredSkipLB      statedb.RWTable[*desiredSkipLB]
	Map                lbmaps.SkipLBMap
	EM                 endpointmanager.EndpointManager `optional:"true"`
	NetNSCookieSupport reflectors.HaveNetNSCookieSupport
}

func registerSkipLBReconciler(p skiplbParams, rp reconciler.Params) {
	if !p.IsEnabled {
		return
	}

	// Register endpoint subscriber. In tests the cookies are inserted directly
	// to the table.
	if p.EM != nil {
		sub := &skiplbEndpointSubscriber{
			db:            p.DB,
			desiredSkipLB: p.DesiredSkipLB,
		}
		p.Lifecycle.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				if p.NetNSCookieSupport() {
					p.EM.Subscribe(sub)
				}
				return nil
			},
			OnStop: func(cell.HookContext) error {
				if p.NetNSCookieSupport() {
					p.EM.Unsubscribe(sub)
				}
				return nil
			},
		})
	}

	// Register reconciler for the SkipLBMap
	reconciler.Register(
		rp,
		p.DesiredSkipLB,
		(*desiredSkipLB).clone,
		func(dsl *desiredSkipLB, s reconciler.Status) *desiredSkipLB {
			dsl.Status = s
			return dsl
		},
		func(dsl *desiredSkipLB) reconciler.Status {
			return dsl.Status
		},
		&skiplbOps{p.Map},
		nil,
	)
}

func skipRedirectsEqual(a, b map[loadbalancer.ServiceName][]loadbalancer.L3n4Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for k, addrA := range a {
		addrB, ok := b[k]
		if !ok {
			return false
		}
		if !slices.Equal(addrA, addrB) {
			return false
		}
	}
	return true
}

type desiredSkipLB struct {
	PodNamespacedName        string
	LRPID                    loadbalancer.ServiceName
	SkipRedirectForFrontends map[loadbalancer.ServiceName][]loadbalancer.L3n4Addr
	ReconciledAddrs          sets.Set[loadbalancer.L3n4Addr]
	NetnsCookie              *uint64
	Status                   reconciler.Status
}

func newDesiredSkipLB(lrpID loadbalancer.ServiceName, pod string) *desiredSkipLB {
	return &desiredSkipLB{
		PodNamespacedName:        pod,
		LRPID:                    lrpID,
		SkipRedirectForFrontends: map[loadbalancer.ServiceName][]loadbalancer.L3n4Addr{},
	}
}

func (dsl *desiredSkipLB) TableHeader() []string {
	return []string{
		"Pod",
		"LocalRedirectPolicy",
		"SkipRedirects",
		"NetnsCookie",
		"Status",
		"Since",
	}
}

func (dsl *desiredSkipLB) TableRow() []string {
	cookie := "<unset>"
	if dsl.NetnsCookie != nil {
		cookie = strconv.FormatUint(*dsl.NetnsCookie, 10)
	}
	var skipRedirects []string
	for _, addrs := range dsl.SkipRedirectForFrontends {
		for _, addr := range addrs {
			skipRedirects = append(skipRedirects, addr.StringWithProtocol())
		}
	}
	sort.Strings(skipRedirects)

	return []string{
		dsl.PodNamespacedName,
		dsl.LRPID.String(),
		strings.Join(skipRedirects, ", "),
		cookie,
		dsl.Status.Kind.String(),
		duration.HumanDuration(time.Since(dsl.Status.UpdatedAt)),
	}
}

func (dsl *desiredSkipLB) clone() *desiredSkipLB {
	copy := *dsl
	return &copy
}

var (
	desiredSkipLBPodIndex = statedb.Index[*desiredSkipLB, string]{
		Name: "pod-name",
		FromObject: func(obj *desiredSkipLB) index.KeySet {
			return index.NewKeySet(index.String(obj.PodNamespacedName))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	desiredSkipLBLRPIndex = statedb.Index[*desiredSkipLB, loadbalancer.ServiceName]{
		Name: "lrp-id",
		FromObject: func(obj *desiredSkipLB) index.KeySet {
			return index.NewKeySet(index.String(obj.LRPID.String()))
		},
		FromKey:    index.Stringer[loadbalancer.ServiceName],
		FromString: index.FromString,
		Unique:     false,
	}
)

func newDesiredSkipLBTable(db *statedb.DB) (statedb.RWTable[*desiredSkipLB], error) {
	return statedb.NewTable(
		db,
		"desired-skiplbmap",
		desiredSkipLBPodIndex,
		desiredSkipLBLRPIndex,
	)
}

type skiplbOps struct {
	m lbmaps.SkipLBMap
}

// Delete implements reconciler.Operations.
func (ops *skiplbOps) Delete(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, d *desiredSkipLB) (err error) {
	if d.NetnsCookie == nil {
		return nil
	}

	for addr := range d.ReconciledAddrs {
		var deleteErr error
		if addr.IsIPv6() {
			deleteErr = ops.m.DeleteLB6(&lbmaps.SkipLB6Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.Addr().As16(),
				Port:        addr.Port(),
			})
		} else {
			deleteErr = ops.m.DeleteLB4(&lbmaps.SkipLB4Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.Addr().As4(),
				Port:        addr.Port(),
			})
		}
		if deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			err = errors.Join(err, deleteErr)
		}
	}

	return
}

// Prune implements reconciler.Operations.
func (ops *skiplbOps) Prune(ctx context.Context, txn statedb.ReadTxn, objs iter.Seq2[*desiredSkipLB, statedb.Revision]) (err error) {
	// Collect the known netns cookies of all existing endpoints.
	known := sets.New[uint64]()
	for d := range objs {
		if d.NetnsCookie != nil {
			known.Insert(*d.NetnsCookie)
		}
	}
	// Remove SkipLB entries that have unknown cookies.
	for key := range ops.m.AllLB4() {
		if !known.Has(key.NetnsCookie) {
			if deleteErr := ops.m.DeleteLB4(key); deleteErr != nil {
				err = errors.Join(err, deleteErr)
			}
		}
	}
	for key := range ops.m.AllLB6() {
		if !known.Has(key.NetnsCookie) {
			if deleteErr := ops.m.DeleteLB6(key); deleteErr != nil {
				err = errors.Join(err, deleteErr)
			}
		}
	}
	return
}

// Update implements reconciler.Operations.
func (ops *skiplbOps) Update(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, d *desiredSkipLB) (err error) {
	if d.NetnsCookie == nil {
		return nil
	}

	newAddrs := sets.New[loadbalancer.L3n4Addr]()
	for _, addrs := range d.SkipRedirectForFrontends {
		for _, addr := range addrs {
			var addErr error
			if addr.IsIPv6() {
				addErr = ops.m.AddLB6(*d.NetnsCookie, addr.AddrCluster().AsNetIP(), addr.Port())
			} else {
				addErr = ops.m.AddLB4(*d.NetnsCookie, addr.AddrCluster().AsNetIP(), addr.Port())
			}
			if addErr != nil {
				err = errors.Join(err, addErr)
			}
			newAddrs.Insert(addr)
		}
	}

	// Remove orphans
	for addr := range d.ReconciledAddrs.Difference(newAddrs) {
		var deleteErr error
		if addr.IsIPv6() {
			deleteErr = ops.m.DeleteLB6(&lbmaps.SkipLB6Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.Addr().As16(),
				Port:        addr.Port(),
			})
		} else {
			deleteErr = ops.m.DeleteLB4(&lbmaps.SkipLB4Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.Addr().As4(),
				Port:        addr.Port(),
			})
		}
		if deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			err = errors.Join(err, deleteErr)
		}
	}

	d.ReconciledAddrs = newAddrs

	return
}

var _ reconciler.Operations[*desiredSkipLB] = &skiplbOps{}

// skiplbEndpointSubscriber adds the netnsCookie information into the Table[desiredSkipLB]
// table.
type skiplbEndpointSubscriber struct {
	db            *statedb.DB
	desiredSkipLB statedb.RWTable[*desiredSkipLB]
}

var _ endpointmanager.Subscriber = &skiplbEndpointSubscriber{}

// EndpointCreated implements endpointmanager.Subscriber.
func (sub *skiplbEndpointSubscriber) EndpointCreated(ep *endpoint.Endpoint) {
	if !ep.K8sNamespaceAndPodNameIsSet() {
		return
	}

	cookie := ep.NetNsCookie

	wtxn := sub.db.WriteTxn(sub.desiredSkipLB)
	defer wtxn.Commit()

	var dsl *desiredSkipLB
	if old, _, found := sub.desiredSkipLB.Get(wtxn, desiredSkipLBPodIndex.Query(ep.GetK8sNamespaceAndPodName())); found {
		dsl = old.clone()
	} else {
		dsl = newDesiredSkipLB(loadbalancer.ServiceName{}, ep.GetK8sNamespaceAndPodName())
	}
	dsl.NetnsCookie = &cookie
	sub.desiredSkipLB.Insert(wtxn, dsl)
}

// EndpointDeleted implements endpointmanager.Subscriber.
func (sub *skiplbEndpointSubscriber) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	if !ep.K8sNamespaceAndPodNameIsSet() {
		return
	}

	wtxn := sub.db.WriteTxn(sub.desiredSkipLB)
	defer wtxn.Commit()
	sub.desiredSkipLB.Delete(
		wtxn,
		newDesiredSkipLB(loadbalancer.ServiceName{}, ep.GetK8sNamespaceAndPodName()),
	)
}

// EndpointRestored implements endpointmanager.Subscriber.
func (sub *skiplbEndpointSubscriber) EndpointRestored(ep *endpoint.Endpoint) {
	sub.EndpointCreated(ep)
}

// TestSkipLBMap is a SkipLBMap that the test suite can provide to override the
// map implementation.
type TestSkipLBMap lbmaps.SkipLBMap

type skiplbmapParams struct {
	cell.In

	Logger             *slog.Logger
	TestSkipLBMap      TestSkipLBMap `optional:"true"`
	Lifecycle          cell.Lifecycle
	NetNSCookieSupport reflectors.HaveNetNSCookieSupport
}

func newSkipLBMap(p skiplbmapParams) (out bpf.MapOut[lbmaps.SkipLBMap], err error) {
	if p.TestSkipLBMap != nil {
		m := lbmaps.SkipLBMap(p.TestSkipLBMap)
		out = bpf.NewMapOut(m)
		return
	}

	var m lbmaps.SkipLBMap
	m, err = lbmaps.NewSkipLBMap(p.Logger)
	if err != nil {
		return
	}

	if os.Getuid() != 0 {
		return
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})
	out = bpf.NewMapOut(m)
	return
}

func newSkipLBMapCommand(m lbmaps.SkipLBMap) hive.ScriptCmdsOut {
	if m == nil {
		return hive.NewScriptCmds(nil)
	}
	return hive.NewScriptCmds(map[string]script.Cmd{
		"skiplbmap": script.Command(
			script.CmdUsage{
				Summary: "Dump the SkipLBMap to file",
				Args:    "file",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("%w: output file needed", script.ErrUsage)
				}
				file, err := os.OpenFile(s.Path(args[0]), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					return nil, err
				}
				defer file.Close()
				var out []string

				for key := range m.AllLB4() {
					addr := net.IP(key.Address[:])
					out = append(out, fmt.Sprintf("COOKIE=%d IP=%s PORT=%d\n",
						key.NetnsCookie,
						addr,
						key.Port,
					))
				}
				for key := range m.AllLB6() {
					addr := net.IP(key.Address[:])
					out = append(out, fmt.Sprintf("COOKIE=%d IP=%s PORT=%d\n",
						key.NetnsCookie,
						addr,
						key.Port,
					))
				}

				// Sort since the iteration order of lock.Map is undeterministic.
				sort.Strings(out)
				for _, line := range out {
					fmt.Fprint(file, line)
				}

				return nil, nil
			},
		),
	})
}
