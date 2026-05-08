// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter_test

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"go.yaml.in/yaml/v3"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

const defaultFileMode = 0o644

type testState struct {
	mu        lock.Mutex
	exporters map[string]exporter.FlowLogExporter
	logger    *slog.Logger
}

type exporterConfig struct {
	Name               string                `yaml:"name"`
	FilePath           string                `yaml:"filePath"`
	FieldMask          []string              `yaml:"fieldMask"`
	AggregationOptions *aggregationOptions   `yaml:"aggregationOptions"`
	IncludeFilters     []map[string][]string `yaml:"includeFilters"`
	ExcludeFilters     []map[string][]string `yaml:"excludeFilters"`
}

type aggregationOptions struct {
	WindowInterval    string   `yaml:"windowInterval"`
	AggregationFields []string `yaml:"aggregationFields"`
}

type multiExporterConfig struct {
	Exporters []exporterConfig `yaml:"exporters"`
}

func TestScript(t *testing.T) {
	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
	}
	log := hivetest.Logger(t, opts...)

	setup := func(t testing.TB, args []string) *script.Engine {
		state := &testState{
			exporters: make(map[string]exporter.FlowLogExporter),
			logger:    log,
		}

		cmds := map[string]script.Cmd{
			"config/add":      configAddCmd(state),
			"config/delete":   configDeleteCmd(state),
			"event/send":      eventSendCmd(state),
			"file/read":       fileReadCmd(),
			"file/exists":     fileExistsCmd(),
			"exporters/count": exportersCountCmd(state),
			"sleep":           sleepCmd(),
		}
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    20 * time.Millisecond,
			MaxRetryInterval: time.Second,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{},
		"testdata/scripts/*.txtar")
}

// parseConfigFile reads and parses a config file, returning either single or multiple exporter configs
func parseConfigFile(configPath string) ([]exporterConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Try to parse as multi-exporter config first
	var multiConfig multiExporterConfig
	if err := yaml.Unmarshal(data, &multiConfig); err == nil && len(multiConfig.Exporters) > 0 {
		return multiConfig.Exporters, nil
	}

	// Try single exporter config
	var config exporterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return []exporterConfig{config}, nil
}

func configAddCmd(state *testState) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add or update exporter configuration",
			Args:    "file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("usage: config/add <file>")
			}

			configs, err := parseConfigFile(s.Path(args[0]))
			if err != nil {
				return nil, err
			}

			for _, cfg := range configs {
				if err := createExporter(s, state, cfg); err != nil {
					return nil, err
				}
			}

			return nil, nil
		},
	)
}

func createExporter(s *script.State, state *testState, config exporterConfig) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	// Expand environment variables in file path (e.g., $WORK)
	filePath := s.ExpandEnv(config.FilePath, false)

	// Build options
	opts := []exporter.Option{
		exporter.WithNewWriterFunc(exporter.FileWriter(exporter.FileWriterConfig{
			Filename: filePath,
		})),
	}

	// Add field mask if specified
	if len(config.FieldMask) > 0 {
		opts = append(opts, exporter.WithFieldMask(config.FieldMask))
	}

	// Add aggregation if specified
	if config.AggregationOptions != nil {
		if len(config.AggregationOptions.AggregationFields) > 0 {
			opts = append(opts, exporter.WithFieldAggregate(config.AggregationOptions.AggregationFields))
		}
		if config.AggregationOptions.WindowInterval != "" {
			duration, err := time.ParseDuration(config.AggregationOptions.WindowInterval)
			if err != nil {
				return fmt.Errorf("invalid window interval: %w", err)
			}
			opts = append(opts, exporter.WithAggregationInterval(duration))
		}
	}

	// Add filters if specified
	if len(config.IncludeFilters) > 0 {
		filters, err := convertToFlowFilters(config.IncludeFilters)
		if err != nil {
			return fmt.Errorf("invalid include filters: %w", err)
		}
		opts = append(opts, exporter.WithAllowList(state.logger, filters))
	}

	if len(config.ExcludeFilters) > 0 {
		filters, err := convertToFlowFilters(config.ExcludeFilters)
		if err != nil {
			return fmt.Errorf("invalid exclude filters: %w", err)
		}
		opts = append(opts, exporter.WithDenyList(state.logger, filters))
	}

	// Create exporter
	exp, err := exporter.NewExporter(state.logger, opts...)
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	state.exporters[config.Name] = exp
	return nil
}

// convertToFlowFilters converts YAML filter maps to FlowFilter protobuf objects
func convertToFlowFilters(filterMaps []map[string][]string) ([]*flowpb.FlowFilter, error) {
	filters := make([]*flowpb.FlowFilter, 0, len(filterMaps))

	for _, filterMap := range filterMaps {
		filter := &flowpb.FlowFilter{}

		for key, values := range filterMap {
			switch key {
			case "sourcePod":
				filter.SourcePod = values
			case "destinationPod":
				filter.DestinationPod = values
			default:
				return nil, fmt.Errorf("Uncovered filter field: %s", key)
			}
		}

		filters = append(filters, filter)
	}

	return filters, nil
}

func configDeleteCmd(state *testState) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete exporter configuration",
			Args:    "file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("usage: config/delete <file>")
			}

			configs, err := parseConfigFile(s.Path(args[0]))
			if err != nil {
				return nil, err
			}

			for _, cfg := range configs {
				deleteExporter(state, cfg.Name)
			}

			return nil, nil
		},
	)
}

func deleteExporter(state *testState, name string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if exp, ok := state.exporters[name]; ok {
		exp.Stop()
		delete(state.exporters, name)
	}
}

func eventSendCmd(state *testState) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Send a flow event to all active exporters",
			Args:    "file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("usage: event/send <file>")
			}

			eventPath := s.Path(args[0])
			data, err := os.ReadFile(eventPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read event: %w", err)
			}

			var flow flowpb.Flow
			if err := json.Unmarshal(data, &flow); err != nil {
				return nil, fmt.Errorf("failed to parse event: %w", err)
			}

			ev := &v1.Event{
				Event: &flow,
			}

			state.mu.Lock()
			defer state.mu.Unlock()

			for _, exp := range state.exporters {
				if err := exp.Export(context.Background(), ev); err != nil {
					return nil, fmt.Errorf("failed to export event: %w", err)
				}
			}

			return nil, nil
		},
	)
}

func fileReadCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Read file contents to output file",
			Args:    "source dest",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("usage: file/read <source> <dest>")
			}

			data, err := os.ReadFile(args[0])
			if err != nil {
				return nil, fmt.Errorf("failed to read file: %w", err)
			}

			destPath := s.Path(args[1])
			if err := os.WriteFile(destPath, data, defaultFileMode); err != nil {
				return nil, fmt.Errorf("failed to write output: %w", err)
			}

			return nil, nil
		},
	)
}

func fileExistsCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Check if file exists",
			Args:    "path",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("usage: file/exists <path>")
			}

			if _, err := os.Stat(args[0]); err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("file does not exist: %s", args[0])
				}
				return nil, err
			}

			return nil, nil
		},
	)
}

func exportersCountCmd(state *testState) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Check number of active exporters",
			Args:    "expected",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("usage: exporters/count <expected>")
			}

			expected := args[0]

			state.mu.Lock()
			actual := fmt.Sprintf("%d", len(state.exporters))
			state.mu.Unlock()

			if actual != expected {
				return nil, fmt.Errorf("expected %s exporters, got %s", expected, actual)
			}
			return nil, nil
		},
	)
}

func sleepCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Sleep for a duration",
			Args:    "duration",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("usage: sleep <duration>")
			}

			duration, err := time.ParseDuration(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid duration: %w", err)
			}

			time.Sleep(duration)
			return nil, nil
		},
	)
}
