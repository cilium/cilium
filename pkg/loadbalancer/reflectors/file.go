// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/pflag"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// StateFile defines the format for the state file used with --lb-state-file.
type StateFile struct {
	Services  []slim_corev1.Service            `json:"services"`
	Endpoints []slim_discoveryv1.EndpointSlice `json:"endpoints"`
}

// FileReflectorCell synchronizes the load-balancing state from a file specified with --lb-state-file.
// The file format is specified by [StateFile] and consists of Kubernetes services and endpoint slices.
//
// The Kubernetes definitions are used to avoid having a new format and conversions from that format
// and it is also familiar to users.
//
// The implementation is tested by 'pkg/loadbalancer/tests/testdata/file.txtar' which also shows
// an example of the file format.
var FileReflectorCell = cell.Module(
	"file-reflector",
	"Synchronizes load-balancing state from a file",

	cell.Config(fileReflectorConfig{}),
	cell.Invoke(registerFileReflector),
)

const (
	logfieldServiceCount  = "serviceCount"
	logfieldFrontendCount = "frontendCount"
	logfieldBackendCount  = "backendCount"
)

type fileReflectorConfig struct {
	LBStateFile         string        `mapstructure:"lb-state-file"`
	LBStateFileInterval time.Duration `mapstructure:"lb-state-file-interval"`
}

func (_ fileReflectorConfig) Flags(flags *pflag.FlagSet) {
	flags.String("lb-state-file", "", "Synchronize load-balancing state from the specified file")
	flags.Duration("lb-state-file-interval", time.Second, "Amount of time to wait for load-balancing state file to settle before processing it")
	flags.MarkHidden("lb-state-file-interval")
}

func registerFileReflector(log *slog.Logger, jg job.Group, lbcfg loadbalancer.Config, extcfg loadbalancer.ExternalConfig, cfg fileReflectorConfig, w *writer.Writer) error {
	if cfg.LBStateFile == "" || !lbcfg.EnableExperimentalLB {
		return nil
	}

	file := cfg.LBStateFile
	isYAML := false
	switch {
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		isYAML = true
	case strings.HasSuffix(file, ".json"):
		isYAML = false
	default:
		return fmt.Errorf("could not deduce file format from %q, expected .json or .yaml suffix", file)
	}
	ls := fileReflector{
		log:       log,
		cfg:       cfg,
		lbConfig:  lbcfg,
		extConfig: extcfg,
		file:      file,
		isYAML:    isYAML,
		w:         w,
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

// fileReflector syncs Source=LocalAPI state from a file containing a
// [structs.LoadBalancerState].
type fileReflector struct {
	log       *slog.Logger
	cfg       fileReflectorConfig
	lbConfig  loadbalancer.Config
	extConfig loadbalancer.ExternalConfig
	file      string
	isYAML    bool
	w         *writer.Writer
}

func (s *fileReflector) syncLoop(ctx context.Context, health cell.Health) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
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

	settleTimer := time.NewTimer(s.cfg.LBStateFileInterval)
	defer settleTimer.Stop()

	for {
		if state, err := s.load(); err != nil {
			s.log.Error("Failed to synchronize",
				logfields.File, s.file,
				logfields.Error, err)
		} else {
			txn := s.w.WriteTxn()
			if numServices, numFrontends, numBackends, err := s.synchronize(txn, state); err == nil {
				txn.Commit()
				s.log.Info("Synchronized from local state",
					logfields.File, s.file,
					logfieldServiceCount, numServices,
					logfieldFrontendCount, numFrontends,
					logfieldBackendCount, numBackends)
			} else {
				s.log.Error("Failed to synchronize",
					logfields.File, s.file,
					logfields.Error, err)
				txn.Abort()
			}
		}

		// Wait for the state file to change. After the first change we'll wait
		// for [fileReflectorConfig.LBStateFileInterval] before processing it.
		var timeout <-chan time.Time
		ready := false
		for !ready {
			select {
			case ev := <-watcher.Events:
				if path.Base(ev.Name) != path.Base(s.file) {
					// Not the file we're looking for.
					continue
				}
				if ev.Op == fsnotify.Remove {
					// Ignore removals. To clear out the local state an empty file is expected.
					continue
				}
				// Reset the timer. Each subsequent modification to the file pushes the
				// processing time back by [LBStateFileInterval].
				settleTimer.Reset(s.cfg.LBStateFileInterval)
				timeout = settleTimer.C
			case <-ctx.Done():
				return nil
			case <-timeout:
				ready = true
			}
		}
	}
}

func (s *fileReflector) load() (*StateFile, error) {
	b, err := os.ReadFile(s.file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)

	}
	var state StateFile

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

func (s *fileReflector) synchronize(txn writer.WriteTxn, state *StateFile) (numServices, numFrontends, numBackends int, err error) {
	// Delete all existing source=LocalAPI services/frontends/backends.
	err = s.w.DeleteServicesBySource(txn, source.LocalAPI)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to delete services: %w", err)
	}
	err = s.w.DeleteBackendsBySource(txn, source.LocalAPI)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to delete backends: %w", err)
	}
	for i := range state.Services {
		svc, fes := convertService(s.lbConfig, s.extConfig, s.log, nil, &state.Services[i], source.LocalAPI)
		if err := s.w.UpsertServiceAndFrontends(txn, svc, fes...); err != nil {
			return 0, 0, 0, fmt.Errorf("failed to upsert services and frontends: %w", err)
		}
		numServices++
		numFrontends += len(fes)
	}
	for i := range state.Endpoints {
		eps := k8s.ParseEndpointSliceV1(s.log, &state.Endpoints[i])
		svcName, bes := convertEndpoints(s.log, s.extConfig, eps)
		if err := s.w.UpsertBackends(txn, svcName, source.LocalAPI, bes...); err != nil {
			return 0, 0, 0, fmt.Errorf("failed to upsert backends: %w", err)
		}
		numBackends++
	}
	return
}
