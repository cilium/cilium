// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/api/structs"
	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

func scriptCommands(
	cfg Config, db *statedb.DB, w *Writer,
	m LBMaps, r reconciler.Reconciler[*Frontend],
) hive.ScriptCmdsOut {
	if !cfg.EnableExperimentalLB {
		return hive.ScriptCmdsOut{}
	}

	var snapshot mapSnapshots
	return hive.NewScriptCmds(map[string]script.Cmd{
		"lb/prune": script.Command(
			script.CmdUsage{Summary: "Trigger pruning of load-balancing BPF maps"},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				r.Prune()
				return nil, nil
			},
		),
		"lb/maps-dump":     lbmapDumpCommand(m),
		"lb/maps-snapshot": lbmapSnapshotCommand(m, &snapshot),
		"lb/maps-restore":  lbmapRestoreCommand(m, &snapshot),

		"lb/service":  serviceCommand(w),
		"lb/frontend": frontendCommand(w),
		"lb/backend":  backendCommand(w),
		"lb/sync":     syncCommand(db, w),
	})
}

func serviceCommand(w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert or delete a service",
			Args:    "[-delete] [flags] service-name",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			reorderArgs(args)
			flags := flag.NewFlagSet("lb/service", flag.ContinueOnError)
			flags.SetOutput(s.LogWriter())
			delete := flags.Bool("delete", false, "Delete the service and all associated frontends")
			extTrafficPolicy := enumFlag(flags, "ext-traffic-policy", loadbalancer.SVCTrafficPolicyCluster, loadbalancer.SVCTrafficPolicies, "external traffic policy")
			intTrafficPolicy := enumFlag(flags, "int-traffic-policy", loadbalancer.SVCTrafficPolicyCluster, loadbalancer.SVCTrafficPolicies, "internal traffic policy")
			natPolicy := enumFlag(flags, "nat-policy", loadbalancer.SVCNatPolicyNone, loadbalancer.SVCNatPolicies, "protocol NAT policy")
			healthCheckNodePort := flags.Int("health-check-nodeport", 0, "NodePort health checker port number, 0 is disabled")
			if err := flags.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil, nil
				}
				return nil, script.ErrUsage
			}
			args = flags.Args()
			if len(args) < 1 {
				return nil, script.ErrUsage
			}

			var serviceName loadbalancer.ServiceName
			if namespace, name, found := strings.Cut(args[0], "/"); found {
				serviceName.Namespace = namespace
				serviceName.Name = name
			} else {
				return nil, fmt.Errorf("%q is an invalid service name", args[0])
			}

			txn := w.WriteTxn()
			var err error
			if *delete {
				err = w.DeleteServiceAndFrontends(txn, serviceName)
				if err == nil {
					s.Logf("Deleted service %q\n", serviceName)
				}
			} else {
				var old *Service
				old, err = w.UpsertService(txn, &Service{
					Name:                   serviceName,
					Source:                 source.LocalAPI,
					Labels:                 nil,
					Annotations:            nil,
					NatPolicy:              *natPolicy,
					ExtTrafficPolicy:       *extTrafficPolicy,
					IntTrafficPolicy:       *intTrafficPolicy,
					SessionAffinity:        false,
					SessionAffinityTimeout: 0,
					ProxyRedirect:          nil,
					HealthCheckNodePort:    uint16(*healthCheckNodePort),
					LoopbackHostPort:       false,
					SourceRanges:           nil,
				})
				if err == nil {
					if old == nil {
						s.Logf("Added service %q\n", serviceName)
					} else {
						s.Logf("Updated service %q\n", serviceName)
					}
				}
			}
			txn.Commit()
			return nil, err
		},
	)
}

func frontendCommand(w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert or delete frontends",
			Args:    "[flags] service-name frontend-address...",
			Detail: []string{
				"See 'lb/frontend -h' for supported flags.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			reorderArgs(args)
			flags := flag.NewFlagSet("lb/frontend", flag.ContinueOnError)
			flags.SetOutput(s.LogWriter())
			serviceType := enumFlag(flags, "type", loadbalancer.SVCTypeClusterIP, loadbalancer.SVCTypes, "Service type")
			portName := flags.String("portname", "", "Port name")
			delete := flags.Bool("delete", false, "Delete the service and associated frontends")
			if err := flags.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil, nil
				}
				return nil, script.ErrUsage
			}
			args = flags.Args()
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			var serviceName loadbalancer.ServiceName
			if namespace, name, found := strings.Cut(args[0], "/"); found {
				serviceName.Namespace = namespace
				serviceName.Name = name
			} else {
				return nil, fmt.Errorf("%q is an invalid service name", args[0])
			}

			var addrs []loadbalancer.L3n4Addr
			for _, arg := range args[1:] {
				frontend, err := loadbalancer.NewL3n4AddrFromString(arg)
				if err != nil {
					return nil, fmt.Errorf("%q is an invalid frontend address: %w", arg, err)
				}
				addrs = append(addrs, *frontend)
			}

			txn := w.WriteTxn()
			defer txn.Abort()

			var err error
			if *delete {
				for _, addr := range addrs {
					_, err = w.DeleteFrontend(txn, addr)
					if err != nil {
						return nil, err
					} else {
						s.Logf("Deleted frontend %q\n", addr.StringWithProtocol())
					}
				}
			} else {
				for _, addr := range addrs {
					var old *Frontend
					old, err = w.UpsertFrontend(txn, FrontendParams{
						Address:     addr,
						Type:        *serviceType,
						ServiceName: serviceName,
						PortName:    loadbalancer.FEPortName(*portName),
						ServicePort: addr.Port,
					})
					if err != nil {
						return nil, err
					} else {
						if old == nil {
							s.Logf("Added frontend %q\n", addr.StringWithProtocol())
						} else {
							s.Logf("Updated frontend %q\n", addr.StringWithProtocol())
						}
					}
				}
			}
			txn.Commit()
			return nil, nil
		},
	)
}

// TODO: switch BackendState from uint8 into a string.
var backendStateModels = []string{
	models.BackendAddressStateActive,
	models.BackendAddressStateTerminating,
	models.BackendAddressStateQuarantined,
	models.BackendAddressStateMaintenance,
}

func backendCommand(w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert or delete backends",
			Args:    "[flags] service-name backend-address...",
			Detail: []string{
				"See 'lb/backend -h' for supported flags.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			reorderArgs(args)
			flags := flag.NewFlagSet("lb/backend", flag.ContinueOnError)
			flags.SetOutput(s.LogWriter())
			delete := flags.Bool("delete", false, "Delete the backend(s)")
			portName := flags.String("portname", "", "Port name")
			stateModel := enumFlag(flags, "state", models.BackendAddressStateActive, backendStateModels, "State")

			weight := flags.Int("weight", 100, "Maglev weight")
			if err := flags.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil, nil
				}
				return nil, script.ErrUsage
			}
			args = flags.Args()
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			state, err := loadbalancer.GetBackendState(*stateModel)
			if err != nil {
				return nil, fmt.Errorf("%q is invalid state: %w", *stateModel, err)
			}
			if *weight == 0 {
				state = loadbalancer.BackendStateMaintenance
			}

			var serviceName loadbalancer.ServiceName
			if namespace, name, found := strings.Cut(args[0], "/"); found {
				serviceName.Namespace = namespace
				serviceName.Name = name
			} else {
				return nil, fmt.Errorf("%q is an invalid service name", args[0])
			}

			var addrs []loadbalancer.L3n4Addr
			for _, arg := range args[1:] {
				frontend, err := loadbalancer.NewL3n4AddrFromString(arg)
				if err != nil {
					return nil, fmt.Errorf("%q is an invalid frontend address: %w", arg, err)
				}
				addrs = append(addrs, *frontend)
			}

			txn := w.WriteTxn()
			defer txn.Abort()

			if *delete {
				for _, addr := range addrs {
					err = w.ReleaseBackend(txn, serviceName, addr)
					if err != nil {
						return nil, err
					}
					s.Logf("Released backend %q for %q\n", addr.StringWithProtocol(), serviceName)
				}
			} else {
				var backends []BackendParams
				for _, addr := range addrs {
					be := BackendParams{
						L3n4Addr: addr,
						PortName: *portName,
						Weight:   uint16(*weight),
						NodeName: "", // TODO
						ZoneID:   0,  // TODO
						State:    state,
					}
					backends = append(backends, be)
				}
				err = w.UpsertBackends(
					txn, serviceName, source.LocalAPI,
					backends...)
				if err != nil {
					return nil, err
				}
				s.Logf("Upserted backends %v\n", addrs)
			}

			txn.Commit()
			return nil, nil
		},
	)
}

func syncCommand(db *statedb.DB, w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Synchronize load-balancing state",
			Args:    "file",
			Detail: []string{
				"Reads the state from given file and synchronizes 'Local'",
				"services and backends.",
				"",
				"The format of the file is specified in 'api/structs/loadbalancer.go'",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}
			filename := args[0]
			b, err := os.ReadFile(s.Path(filename))
			if err != nil {
				return nil, err
			}
			var state structs.LoadBalancerState
			switch {
			case strings.HasSuffix(filename, ".yaml"), strings.HasSuffix(filename, ".yml"):
				err = yaml.Unmarshal(b, &state)
			case strings.HasSuffix(filename, ".json"):
				err = json.Unmarshal(b, &state)
			default:
				return nil, fmt.Errorf("could not deduce file format from %q, expected .json or .yaml suffix", filename)
			}
			if err != nil {
				return nil, fmt.Errorf("loading from %q failed: %w", filename, err)
			}

			ls, err := newLocalSynchronizer(db, w)
			if err != nil {
				return nil, err
			}
			return nil, ls.synchronize(&state)
		},
	)
}

func lbmapDumpCommand(m LBMaps) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the load-balancing BPF maps",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the load-balancer BPF maps either to stdout or to a file.",
				"Each BPF map key-value is shown as one line, e.g. backend would be:",
				"BE: ID=1 ADDR=10.244.1.1:80 STATE=active",
				"",
				"Format is not guaranteed to be stable as this command is only",
				"for testing and debugging purposes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				out := DumpLBMaps(
					m,
					false,
					nil,
				)
				data := strings.Join(out, "\n") + "\n"
				if len(args) == 1 {
					err = os.WriteFile(s.Path(args[0]), []byte(data), 0644)
				} else {
					stdout = data
				}
				return
			}, nil
		},
	)
}

func lbmapSnapshotCommand(m LBMaps, snapshot *mapSnapshots) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Snapshot the load-balancing BPF maps",
			Args:    "",
			Detail: []string{
				"Dump the load-balancing BPF maps into an in-memory snapshot",
				"which can be restored with lbmaps/restore. This is meant only",
				"for testing.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, snapshot.snapshot(m)
		},
	)
}

func lbmapRestoreCommand(m LBMaps, snapshot *mapSnapshots) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Restore the load-balancing BPF maps from snapshot",
			Args:    "",
			Detail: []string{
				"Restore the load-balancing BPF map contents from a snapshot",
				"created with lbmaps/snapshot.",
				"The BPF maps are not cleared before restoring, so any existing",
				"values will not be removed.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, snapshot.restore(m)
		},
	)
}

type enumValue[S ~string] struct {
	p    *S
	alts []S
}

func newEnumValue[S ~string](val S, alts []S, p *S) *enumValue[S] {
	*p = val
	return &enumValue[S]{
		p:    p,
		alts: alts,
	}
}

func (ev *enumValue[S]) Set(val string) error {
	val = strings.ToLower(val)
	for _, alt := range ev.alts {
		if strings.ToLower(string(alt)) == val {
			*ev.p = alt
			return nil
		}
	}
	return fmt.Errorf("%q not found from alternatives %v", val, ev.alts)
}

func (ev *enumValue[S]) Get() any {
	if ev == nil || ev.p == nil {
		return nil
	}
	return string(*ev.p)
}

func (ev *enumValue[S]) String() string {
	if ev == nil || ev.p == nil {
		return ""
	}
	return string(*ev.p)
}

func enumFlag[S ~string](fs *flag.FlagSet, name string, value S, alts []S, usage string) *S {
	var p S
	fs.Var(newEnumValue(value, alts, &p), name, fmt.Sprintf("%s (one of %v)", usage, alts))
	return &p
}

// reorderArgs moves all flags to the front.
func reorderArgs(args []string) {
	slices.SortStableFunc(
		args,
		func(a, b string) int {
			switch {
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(b, "-"):
				return -1
			case strings.HasPrefix(b, "-") && !strings.HasPrefix(a, "-"):
				return 1
			default:
				return 0
			}
		},
	)
}

// localSynchronizer syncs Source=LocalAPI state from a file containing a
// [structs.LoadBalancerState].
type localSynchronizer struct {
	txn WriteTxn
	w   *Writer
}

func newLocalSynchronizer(db *statedb.DB, w *Writer) (*localSynchronizer, error) {
	s := &localSynchronizer{
		txn: w.WriteTxn(),
		w:   w,
	}

	// Delete all existing source=LocalAPI services/frontends/backends.
	err := w.DeleteServicesBySource(s.txn, source.LocalAPI)
	if err != nil {
		s.txn.Abort()
		return nil, err
	}
	err = w.DeleteBackendsBySource(s.txn, source.LocalAPI)
	if err != nil {
		s.txn.Abort()
		return nil, err
	}

	return s, nil
}

func (s *localSynchronizer) synchronize(state *structs.LoadBalancerState) error {
	defer func() {
		s.txn.Abort()
		*s = localSynchronizer{}
	}()

	for i := range state.Services {
		if err := s.upsertService(&state.Services[i]); err != nil {
			return err
		}
	}
	s.txn.Commit()
	return nil
}

func (s *localSynchronizer) upsertService(svc *structs.Service) error {
	natPolicy, err := parseNatPolicy(svc.NatPolicy)
	if err != nil {
		return fmt.Errorf("invalid NatPolicy: %w", err)
	}
	intTrafficPolicy, err := parseTrafficPolicy(svc.IntTrafficPolicy)
	if err != nil {
		return fmt.Errorf("invalid IntTrafficPolicy: %w", err)
	}
	extTrafficPolicy, err := parseTrafficPolicy(svc.ExtTrafficPolicy)
	if err != nil {
		return fmt.Errorf("invalid ExtTrafficPolicy: %w", err)
	}

	newSVC := &Service{
		Name: loadbalancer.ServiceName{
			Namespace: svc.Namespace,
			Name:      svc.Name,
		},
		Source:              source.LocalAPI,
		Labels:              nil,
		Annotations:         nil,
		NatPolicy:           natPolicy,
		ExtTrafficPolicy:    intTrafficPolicy,
		IntTrafficPolicy:    extTrafficPolicy,
		HealthCheckNodePort: svc.HealthCheckNodePort,
	}

	if _, err = s.w.UpsertService(s.txn, newSVC); err != nil {
		return err
	}

	for i := range svc.Frontends {
		if err := s.upsertFrontend(newSVC, &svc.Frontends[i]); err != nil {
			return err
		}
	}

	if err := s.upsertBackends(newSVC, svc.Backends); err != nil {
		return err
	}

	return nil
}

func (s *localSynchronizer) upsertFrontend(svc *Service, fe *structs.Frontend) error {
	addr, err := parseAddress(fe.Address)
	if err != nil {
		return err
	}
	typ, err := parseEnum(fe.Type, loadbalancer.SVCTypes)
	if err != nil {
		return fmt.Errorf("invalid Type: %w", err)
	}
	newFE := FrontendParams{
		Address:     addr,
		Type:        typ,
		ServiceName: svc.Name,
		PortName:    loadbalancer.FEPortName(fe.PortName),
		ServicePort: addr.Port,
	}
	_, err = s.w.UpsertFrontend(s.txn, newFE)
	return err
}

func (s *localSynchronizer) upsertBackends(svc *Service, bes []structs.Backend) error {
	params := make([]BackendParams, len(bes))
	for i := range bes {
		be := &bes[i]
		addr, err := parseAddress(be.Address)
		if err != nil {
			return err
		}
		state, err := parseBackendState(be.State)
		if err != nil {
			return err
		}
		params[i] = BackendParams{
			L3n4Addr: addr,
			PortName: "",
			Weight:   be.Weight,
			ZoneID:   0,
			State:    state,
		}
	}
	return s.w.UpsertBackends(s.txn, svc.Name, source.LocalAPI, params...)
}

func parseNatPolicy(s string) (loadbalancer.SVCNatPolicy, error) {
	return parseEnum(s, loadbalancer.SVCNatPolicies)
}

func parseTrafficPolicy(s string) (loadbalancer.SVCTrafficPolicy, error) {
	if s == "" {
		return loadbalancer.SVCTrafficPolicyCluster, nil
	}
	return parseEnum(s, loadbalancer.SVCTrafficPolicies)
}

func parseBackendState(s string) (loadbalancer.BackendState, error) {
	switch strings.ToLower(s) {
	case "", "active":
		return loadbalancer.BackendStateActive, nil
	case "maintenance":
		return loadbalancer.BackendStateMaintenance, nil
	case "terminating":
		return loadbalancer.BackendStateTerminating, nil
	case "quarantined":
		return loadbalancer.BackendStateQuarantined, nil
	default:
		return loadbalancer.BackendStateInvalid,
			fmt.Errorf("%q not valid, expected one of: active, maintenance, terminating or quarantined",
				s,
			)
	}
}

func parseEnum[T ~string](s string, values []T) (T, error) {
	s = strings.ToLower(s)
	for _, v := range values {
		if s == strings.ToLower(string(v)) {
			return v, nil
		}
	}
	return T(""), fmt.Errorf("%q not valid (options: %v)", s, values)
}

func parseAddress(addr structs.Address) (loadbalancer.L3n4Addr, error) {
	addrCluster, err := cmtypes.ParseAddrCluster(addr.IP)
	if err != nil {
		return loadbalancer.L3n4Addr{}, err
	}

	proto := strings.ToUpper(addr.Protocol)
	switch proto {
	}

	var scope uint8
	switch strings.ToLower(addr.Scope) {
	case "", "e", "external":
		scope = loadbalancer.ScopeExternal
	case "i", "internal":
		scope = loadbalancer.ScopeInternal
	default:
		return loadbalancer.L3n4Addr{},
			fmt.Errorf("invalid scope %q, expected 'internal' or 'external'", addr.Scope)
	}
	return loadbalancer.L3n4Addr{
		AddrCluster: addrCluster,
		L4Addr: loadbalancer.L4Addr{
			Protocol: proto,
			Port:     addr.Port,
		},
		Scope: scope,
	}, nil
}
