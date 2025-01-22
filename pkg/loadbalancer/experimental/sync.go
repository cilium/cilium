// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/cilium/cilium/api/structs"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

type localSyncConfig struct {
	LBLocalSyncFile string `mapstructure:"lb-local-sync-file"`
}

func (_ localSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.String("lb-local-sync-file", "", "File to synchronize load-balancing state from")
}

var localSyncCell = cell.Module(
	"local-synchronizer",
	"Synchronizes load-balancing state from a file",

	cell.Config(localSyncConfig{}),
	cell.Invoke(registerLocalSynchronizer),
)

func registerLocalSynchronizer(log *slog.Logger, jg job.Group, lbcfg Config, cfg localSyncConfig, w *Writer) error {
	if cfg.LBLocalSyncFile == "" || !lbcfg.EnableExperimentalLB {
		return nil
	}

	file := cfg.LBLocalSyncFile
	isYAML := false
	switch {
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		isYAML = true
	case strings.HasSuffix(file, ".json"):
		isYAML = false
	default:
		return fmt.Errorf("could not deduce file format from %q, expected .json or .yaml suffix", file)
	}
	ls := localSynchronizer{
		log:    log,
		file:   file,
		isYAML: isYAML,
		w:      w,
	}
	jg.Add(job.OneShot(
		"sync",
		ls.syncLoop,
		job.WithRetry(-1, &job.ExponentialBackoff{
			Min: time.Minute,
			Max: 5 * time.Minute,
		}),
	))
	return nil
}

// localSynchronizer syncs Source=LocalAPI state from a file containing a
// [structs.LoadBalancerState].
type localSynchronizer struct {
	log    *slog.Logger
	file   string
	isYAML bool
	w      *Writer
}

func (s *localSynchronizer) syncLoop(ctx context.Context, health cell.Health) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Watch the parent directory for changes and react to events on the specified
	// file.
	watchDir := "."
	if path.IsAbs(s.file) {
		watchDir = path.Dir(s.file)
	}
	if err := watcher.Add(watchDir); err != nil {
		return fmt.Errorf("failed to watch %q: %w", s.file, err)
	}

	limiter := rate.NewLimiter(time.Second, 5)

	for {
		if state, err := s.load(); err != nil {
			s.log.Error("Failed to synchronize", "file", s.file, "error", err)
		} else {
			txn := s.w.WriteTxn()
			if err := s.synchronize(txn, state); err == nil {
				txn.Commit()
				// TODO summarize the changes
				s.log.Info("Synchronized from local state", "file", s.file)
			} else {
				s.log.Error("Failed to synchronize", "file", s.file, "error", err)
				txn.Abort()
			}
		}

		// Rate limit the reprocessing of changes.
		if err := limiter.Wait(ctx); err != nil {
			return err
		}

	again:
		select {
		case ev := <-watcher.Events:
			if path.Base(ev.Name) != path.Base(s.file) {
				goto again
			}
			if ev.Op == fsnotify.Remove {
				// Ignore removals. To clear out the local state an empty file is expected.
				goto again
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *localSynchronizer) load() (*structs.LoadBalancerState, error) {
	b, err := os.ReadFile(s.file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)

	}
	var state structs.LoadBalancerState

	// TODO: move format detection to constructor
	if s.isYAML {
		err = yaml.Unmarshal(b, &state)
	} else {
		err = json.Unmarshal(b, &state)
	}

	if err != nil {
		return nil, err
	}

	return &state, nil

}

func (s *localSynchronizer) synchronize(txn WriteTxn, state *structs.LoadBalancerState) error {
	// Delete all existing source=LocalAPI services/frontends/backends.
	err := s.w.DeleteServicesBySource(txn, source.LocalAPI)
	if err != nil {
		return err
	}
	err = s.w.DeleteBackendsBySource(txn, source.LocalAPI)
	if err != nil {
		return err
	}

	for i := range state.Services {
		if err := s.upsertService(txn, &state.Services[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *localSynchronizer) upsertService(txn WriteTxn, svc *structs.Service) error {
	newSVC := &Service{
		Name: loadbalancer.ServiceName{
			Namespace: svc.Namespace,
			Name:      svc.Name,
		},
		Source:              source.LocalAPI,
		Labels:              nil,
		Annotations:         nil,
		NatPolicy:           loadbalancer.SVCNatPolicyNone,
		ExtTrafficPolicy:    loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:    loadbalancer.SVCTrafficPolicyCluster,
		HealthCheckNodePort: svc.HealthCheckNodePort,
	}

	if _, err := s.w.UpsertService(txn, newSVC); err != nil {
		return err
	}

	for i := range svc.Frontends {
		if err := s.upsertFrontend(txn, newSVC, &svc.Frontends[i]); err != nil {
			return err
		}
	}

	if err := s.upsertBackends(txn, newSVC, svc.Backends); err != nil {
		return err
	}

	return nil
}

func (s *localSynchronizer) upsertFrontend(txn WriteTxn, svc *Service, fe *structs.Frontend) error {
	addr, err := parseAddress(fe.Address)
	if err != nil {
		return fmt.Errorf("invalid frontend address: %w", err)
	}
	typ, err := parseEnum(fe.Type, loadbalancer.SVCTypeClusterIP, loadbalancer.SVCTypes)
	if err != nil {
		return fmt.Errorf("invalid frontend type: %w", err)
	}
	newFE := FrontendParams{
		Address:     addr,
		Type:        typ,
		ServiceName: svc.Name,
		PortName:    "",
		ServicePort: addr.Port,
	}
	_, err = s.w.UpsertFrontend(txn, newFE)
	return err
}

func (s *localSynchronizer) upsertBackends(txn WriteTxn, svc *Service, bes []structs.Backend) error {
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
	return s.w.UpsertBackends(txn, svc.Name, source.LocalAPI, params...)
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

func parseEnum[T ~string](s string, def T, values []T) (T, error) {
	if s == "" {
		return def, nil
	}
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
	case loadbalancer.NONE, loadbalancer.ANY, loadbalancer.TCP, loadbalancer.UDP, loadbalancer.SCTP:
	case "":
		proto = loadbalancer.TCP
	default:
		return loadbalancer.L3n4Addr{}, fmt.Errorf("invalid L4 protocol %q", proto)
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
