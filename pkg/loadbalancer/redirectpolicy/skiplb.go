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
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/time"
)

type skiplbParams struct {
	cell.In

	Log                *slog.Logger
	IsEnabled          lrpIsEnabled
	DB                 *statedb.DB
	Lifecycle          cell.Lifecycle
	DesiredSkipLB      statedb.RWTable[*desiredSkipLB]
	Map                lbmap.SkipLBMap
	EM                 endpointmanager.EndpointManager `optional:"true"`
	NetNSCookieSupport lbmaps.HaveNetNSCookieSupport
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
		if !slices.EqualFunc(addrA, addrB, func(a, b loadbalancer.L3n4Addr) bool { return a.DeepEqual(&b) }) {
			return false
		}
	}
	return true
}

type desiredSkipLB struct {
	PodNamespacedName        string
	LRPID                    k8s.ServiceID
	SkipRedirectForFrontends map[loadbalancer.ServiceName][]loadbalancer.L3n4Addr
	ReconciledAddrs          sets.Set[loadbalancer.L3n4Addr]
	NetnsCookie              *uint64
	Status                   reconciler.Status
}

func newDesiredSkipLB(lrpID k8s.ServiceID, pod string) *desiredSkipLB {
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
		string(dsl.Status.Kind),
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
	desiredSkipLBLRPIndex = statedb.Index[*desiredSkipLB, k8s.ServiceID]{
		Name: "lrp-id",
		FromObject: func(obj *desiredSkipLB) index.KeySet {
			return index.NewKeySet(index.String(obj.LRPID.String()))
		},
		FromKey:    index.Stringer[k8s.ServiceID],
		FromString: index.FromString,
		Unique:     false,
	}
)

func newDesiredSkipLBTable(db *statedb.DB) (statedb.RWTable[*desiredSkipLB], error) {
	tbl, err := statedb.NewTable(
		"desired-skiplbmap",
		desiredSkipLBPodIndex,
		desiredSkipLBLRPIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

type skiplbOps struct {
	m lbmap.SkipLBMap
}

// Delete implements reconciler.Operations.
func (ops *skiplbOps) Delete(ctx context.Context, txn statedb.ReadTxn, d *desiredSkipLB) (err error) {
	if d.NetnsCookie == nil {
		return nil
	}

	for addr := range d.ReconciledAddrs {
		var deleteErr error
		if addr.IsIPv6() {
			deleteErr = ops.m.DeleteLB6(&lbmap.SkipLB6Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.AddrCluster.Addr().As16(),
				Port:        addr.Port,
			})
		} else {
			deleteErr = ops.m.DeleteLB4(&lbmap.SkipLB4Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.AddrCluster.Addr().As4(),
				Port:        addr.Port,
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
func (ops *skiplbOps) Update(ctx context.Context, txn statedb.ReadTxn, d *desiredSkipLB) (err error) {
	if d.NetnsCookie == nil {
		return nil
	}

	newAddrs := sets.New[loadbalancer.L3n4Addr]()
	for _, addrs := range d.SkipRedirectForFrontends {
		for _, addr := range addrs {
			var addErr error
			if addr.IsIPv6() {
				addErr = ops.m.AddLB6(*d.NetnsCookie, addr.AddrCluster.AsNetIP(), addr.Port)
			} else {
				addErr = ops.m.AddLB4(*d.NetnsCookie, addr.AddrCluster.AsNetIP(), addr.Port)
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
			deleteErr = ops.m.DeleteLB6(&lbmap.SkipLB6Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.AddrCluster.Addr().As16(),
				Port:        addr.Port,
			})
		} else {
			deleteErr = ops.m.DeleteLB4(&lbmap.SkipLB4Key{
				NetnsCookie: *d.NetnsCookie,
				Address:     addr.AddrCluster.Addr().As4(),
				Port:        addr.Port,
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
		dsl = newDesiredSkipLB(k8s.ServiceID{}, ep.GetK8sNamespaceAndPodName())
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
		newDesiredSkipLB(k8s.ServiceID{}, ep.GetK8sNamespaceAndPodName()),
	)
}

// EndpointRestored implements endpointmanager.Subscriber.
func (sub *skiplbEndpointSubscriber) EndpointRestored(ep *endpoint.Endpoint) {
	sub.EndpointCreated(ep)
}

// TestSkipLBMap is a SkipLBMap that the test suite can provide to override the
// map implementation.
type TestSkipLBMap lbmap.SkipLBMap

type skiplbmapParams struct {
	cell.In

	IsEnabled          lrpIsEnabled
	TestSkipLBMap      TestSkipLBMap `optional:"true"`
	Lifecycle          cell.Lifecycle
	NetNSCookieSupport lbmaps.HaveNetNSCookieSupport
}

func newSkipLBMap(p skiplbmapParams) (out bpf.MapOut[lbmap.SkipLBMap], err error) {
	if !p.IsEnabled {
		return
	}

	if p.TestSkipLBMap != nil {
		m := lbmap.SkipLBMap(p.TestSkipLBMap)
		out = bpf.NewMapOut(m)
		return
	}

	var m lbmap.SkipLBMap
	m, err = lbmap.NewSkipLBMap()
	if err != nil {
		return
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if !p.NetNSCookieSupport() {
				return nil
			}
			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})
	out = bpf.NewMapOut(m)
	return
}

func newSkipLBMapCommand(m lbmap.SkipLBMap) hive.ScriptCmdsOut {
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
