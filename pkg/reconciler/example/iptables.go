package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/reconciler"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var (
	RulePrimaryIndex = statedb.Index[*Rule, *Rule]{
		Name: "primary",
		FromObject: func(rule *Rule) index.KeySet {
			return index.NewKeySet(rule.PrimaryKey())
		},
		FromKey: (*Rule).PrimaryKey,
		Unique:  true,
	}
	RuleStatusIndex = reconciler.NewStatusIndex[*Rule]()
)

var IPTablesCell = cell.Module(
	"iptables",
	"IPTables desired state and reconciliation",

	statedb.NewTableCell[*Rule]("iptables-rules", RulePrimaryIndex, RuleStatusIndex),

	cell.ProvidePrivate(
		func() reconciler.Target[*Rule] { return &iptablesTarget{} },
		func() reconciler.Config {
			return reconciler.Config{
				FullReconcilationInterval: 10 * time.Second,
				RetryBackoffMinDuration:   time.Second,
				RetryBackoffMaxDuration:   10 * time.Second,
			}
		},
		func() statedb.Index[*Rule, reconciler.StatusKind] { return RuleStatusIndex },
	),
	cell.Invoke(reconciler.Register[*Rule]),
)

//
// iptables reconciliation target
//

type iptablesTarget struct {
}

// Delete implements reconciler.Target
func (*iptablesTarget) Delete(_ context.Context, txn statedb.ReadTxn, rule *Rule) error {
	fmt.Printf(">>> iptables %s\n", strings.Join(rule.ToArgs("-D"), " "))
	return nil
}

// Update implements reconciler.Target
func (*iptablesTarget) Update(_ context.Context, txn statedb.ReadTxn, rule *Rule) (bool, error) {
	fmt.Printf(">>> iptables %s\n", strings.Join(rule.ToArgs("-A"), " "))
	return true, errors.New("oops iptables error")
}

func (*iptablesTarget) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[*Rule]) error {
	return nil
}

func (*iptablesTarget) Init(context.Context) error {
	// TODO:
	// - Load kernel modules.
	// - Probe for features.
	// - Setup cilium chains.
	return nil
}

var _ reconciler.Target[*Rule] = &iptablesTarget{}

//
// Rule
//

type Rule struct {
	TableChain TableChain
	IPv6       bool
	Comment    string
	Args       []ToArgs
	Jump       Jump
	Status     reconciler.Status
}

func (rule *Rule) GetStatus() reconciler.Status { return rule.Status }

func (rule *Rule) WithStatus(new reconciler.Status) *Rule {
	ruleCopy := *rule
	ruleCopy.Status = new
	return &ruleCopy
}

func (rule *Rule) PrimaryKey() index.Key {
	// TODO: This is pretty expensive. Could the "Comment" make for a reasonable
	// key?
	return index.String(strings.Join(rule.ToArgs("X"), " "))
}

func (rule *Rule) ToArgs(action string) []string {
	args := []string{
		"-t", rule.TableChain.Table,
		action, rule.TableChain.Chain,
		"-m", "comment", "--comment", rule.Comment,
	}
	for _, a := range rule.Args {
		args = append(args, a.ToArgs()...)
	}
	return append(args, rule.Jump.ToArgs()...)
}

//
// Jumps
//

type Jump struct {
	Target string
	Args   []string
}

func (j Jump) ToArgs() (args []string) {
	args = append(args, "-j", j.Target)
	return append(args, j.Args...)
}

var (
	JumpAccept = Jump{Target: "ACCEPT", Args: nil}
	JumpDrop   = Jump{Target: "DROP", Args: nil}
	JumpReject = Jump{Target: "REJECT", Args: nil}
)

func JumpSnat(toSource string, randomFully bool) Jump {
	args := []string{"--to-source", toSource}
	if randomFully {
		args = append(args, "--random-fully")
	}
	return Jump{
		Target: "SNAT",
		Args:   args,
	}
}

func JumpConnMark(setXMark string, nfMask string, ctMask string, restoreMark bool) Jump {
	panic("TBD")
}

//
// Tables and chains
//

type TableChain struct {
	Table, Chain string
}

var (
	TableChainFilterInput   = TableChain{"filter", "INPUT"}
	TableChainFilterForward = TableChain{"filter", "FORWARD"}
	TableChainFilterOutput  = TableChain{"filter", "OUTPUT"}

	TableChainNatPreRouting  = TableChain{"nat", "PREROUTING"}
	TableChainNatInput       = TableChain{"nat", "INPUT"}
	TableChainNatOutput      = TableChain{"nat", "OUTPUT"}
	TableChainNatPostRouting = TableChain{"nat", "POSTROUTING"}

	TableChainManglePreRouting  = TableChain{"mangle", "PREROUTING"}
	TableChainMangleOutput      = TableChain{"mangle", "OUTPUT"}
	TableChainMangleInput       = TableChain{"mangle", "INPUT"}
	TableChainMangleForward     = TableChain{"mangle", "FORWARD"}
	TableChainManglePostRouting = TableChain{"mangle", "POSTROUTING"}

	TableChainRawNoTrack    = TableChain{"raw", "NOTRACK"}
	TableChainRawPreRouting = TableChain{"raw", "PREROUTING"}
	TableChainRawOutput     = TableChain{"raw", "OUTPUT"}

	TableChainSecurityInput   = TableChain{"security", "INPUT"}
	TableChainSecurityOutput  = TableChain{"security", "OUTPUT"}
	TableChainSecurityForward = TableChain{"security", "FORWARD"}

	TableChainFilterCiliumInput  = TableChain{"filter", "CILIUM_INPUT"}
	TableChainFilterCiliumOutput = TableChain{"filter", "CILIUM_OUTPUT"}
	// ...
)

//
// Arguments
//

type ToArgs interface {
	ToArgs() []string
}

type Mark string

func (m Mark) ToArgs() []string {
	return []string{"-m", "mark", "--mark", string(m)}
}

type NegMark string

func (m NegMark) ToArgs() []string {
	return []string{"-m", "mark", "!", "--mark", string(m)}
}

type OutDevice string

func (out OutDevice) ToArgs() []string {
	return []string{"-o", string(out)}
}

type InDevice string

func (in InDevice) ToArgs() []string {
	return []string{"-i", string(in)}
}

type Proto string

func (p Proto) ToArgs() []string {
	return []string{"-p", string(p)}
}

type NotDestination Destination

func (d NotDestination) ToArgs() (args []string) {
	args = append(args, "!")
	return append(args, d.ToArgs()...)
}

type Destination struct {
	IP   netip.Addr
	Port *uint16
}

func (d Destination) ToArgs() (args []string) {
	args = append(args, "-d", d.IP.String())
	if d.Port != nil {
		args = append(args,
			"--dport",
			strconv.FormatUint(uint64(*d.Port), 10))
	}
	return
}

type Source struct {
	IP   netip.Addr
	Port *uint16
}

func (s Source) ToArgs() (args []string) {
	args = append(args, "-s", s.IP.String())
	if s.Port != nil {
		args = append(args,
			"--sport",
			strconv.FormatUint(uint64(*s.Port), 10))
	}
	return
}

type NotSource Source

func (s NotSource) ToArgs() (args []string) {
	args = append(args, "!")
	return append(args, s.ToArgs()...)
}

type NoTrack struct{}

func (NoTrack) ToArgs() []string {
	return []string{"--notrack"}
}

type ConnTrack struct {
	CTState string
}

func (ct ConnTrack) ToArgs() (args []string) {
	return []string{
		"-m", "conntrack",
		"--ctstate", ct.CTState,
		// TODO rest
	}
}
