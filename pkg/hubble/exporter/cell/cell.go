// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package exportercell

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type config struct {
	// FlowlogsConfigFilePath specifies the filepath with configuration of
	// hubble flowlogs. e.g. "/etc/cilium/flowlog.yaml".
	FlowlogsConfigFilePath string `mapstructure:"hubble-flowlogs-config-path"`
	// ExportFilePath specifies the filepath to write Hubble events to. e.g.
	// "/var/run/cilium/hubble/events.log".
	ExportFilePath string `mapstructure:"hubble-export-file-path"`
	// ExportFileMaxSizeMB specifies the file size in MB at which to rotate the
	// Hubble export file.
	ExportFileMaxSizeMB int `mapstructure:"hubble-export-file-max-size-mb"`
	// ExportFileMaxBackups specifies the number of rotated files to keep.
	ExportFileMaxBackups int `mapstructure:"hubble-export-file-max-backups"`
	// ExportFileCompress specifies whether rotated files are compressed.
	ExportFileCompress bool `mapstructure:"hubble-export-file-compress"`
	// ExportAllowlist specifies allow list filter use by exporter.
	ExportAllowlist string `mapstructure:"hubble-export-allowlist"`
	// ExportDenylist specifies deny list filter use by exporter.
	ExportDenylist string `mapstructure:"hubble-export-denylist"`
	// ExportFieldmask specifies list of fields to log in exporter.
	ExportFieldmask []string `mapstructure:"hubble-export-fieldmask"`
}

var DefaultConfig = config{
	FlowlogsConfigFilePath: "",
	ExportFilePath:         "",
	ExportFileMaxSizeMB:    exporter.DefaultFileMaxSizeMB,
	ExportFileMaxBackups:   exporter.DefaultFileMaxBackups,
	ExportFileCompress:     false,
	ExportAllowlist:        "",
	ExportDenylist:         "",
	ExportFieldmask:        []string{},
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.String("hubble-flowlogs-config-path", def.FlowlogsConfigFilePath, "Filepath with configuration of hubble flowlogs")
	flags.String("hubble-export-file-path", def.ExportFilePath, "Filepath to write Hubble events to. By specifying `stdout` the flows are logged instead of written to a rotated file.")
	flags.Int("hubble-export-file-max-size-mb", def.ExportFileMaxSizeMB, "Size in MB at which to rotate Hubble export file.")
	flags.Int("hubble-export-file-max-backups", def.ExportFileMaxBackups, "Number of rotated Hubble export files to keep.")
	flags.Bool("hubble-export-file-compress", def.ExportFileCompress, "Compress rotated Hubble export files.")
	flags.String("hubble-export-allowlist", "", "Specify allowlist as JSON encoded FlowFilters to Hubble exporter.")
	flags.String("hubble-export-denylist", "", "Specify denylist as JSON encoded FlowFilters to Hubble exporter.")
	flags.StringSlice("hubble-export-fieldmask", def.ExportFieldmask, "Specify list of fields to use for field mask in Hubble exporter.")
}

func (cfg config) validate() error {
	if fm := cfg.ExportFieldmask; len(fm) > 0 {
		_, err := fieldmaskpb.New(&flowpb.Flow{}, fm...)
		if err != nil {
			return fmt.Errorf("hubble-export-fieldmask contains invalid fieldmask '%v': %w", fm, err)
		}
	}
	return nil
}

type hubbleExportersParams struct {
	cell.In

	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Config    validatedConfig

	// TODO: replace by slog
	Logger logging.FieldLogger
}

type hubbleExportersOut struct {
	cell.Out

	Exporters []exporter.FlowLogExporter `group:"hubble-flow-log-exporters,flatten"`
}

// validatedConfig is a config that is known to be valid.
type validatedConfig config

func NewValidatedConfig(cfg config) (validatedConfig, error) {
	if err := cfg.validate(); err != nil {
		return validatedConfig{}, fmt.Errorf("hubble-exporter configuration error: %w", err)
	}
	return validatedConfig(cfg), nil
}

func NewHubbleStaticExporter(params hubbleExportersParams) (hubbleExportersOut, error) {
	if params.Config.ExportFilePath == "" {
		// exporter is disabled
		return hubbleExportersOut{}, nil
	}

	allowList, err := hubble.ParseFlowFilters(params.Config.ExportAllowlist)
	if err != nil {
		return hubbleExportersOut{}, fmt.Errorf("failed to parse allowlist: %w", err)
	}
	denyList, err := hubble.ParseFlowFilters(params.Config.ExportDenylist)
	if err != nil {
		return hubbleExportersOut{}, fmt.Errorf("failed to parse denylist: %w", err)
	}

	exporterOpts := []exporter.Option{
		exporter.WithAllowList(params.Logger, allowList),
		exporter.WithDenyList(params.Logger, denyList),
		exporter.WithFieldMask(params.Config.ExportFieldmask),
	}
	if params.Config.ExportFilePath != "stdout" {
		exporterOpts = append(exporterOpts, exporter.WithNewWriterFunc(exporter.FileWriter(exporter.FileWriterConfig{
			Filename:   params.Config.ExportFilePath,
			MaxSize:    params.Config.ExportFileMaxSizeMB,
			MaxBackups: params.Config.ExportFileMaxBackups,
			Compress:   params.Config.ExportFileCompress,
		})))
	}
	staticExporter, err := exporter.NewExporter(params.Logger, exporterOpts...)
	if err != nil {
		// non-fatal failure, log and continue
		params.Logger.Error("Failed to configure Hubble static exporter", slog.Any(logfields.Error, err))
		return hubbleExportersOut{}, nil
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			return staticExporter.Stop()
		},
	})
	return hubbleExportersOut{Exporters: []exporter.FlowLogExporter{staticExporter}}, nil
}

func NewHubbleDynamicExporter(params hubbleExportersParams) (hubbleExportersOut, error) {
	if params.Config.FlowlogsConfigFilePath == "" {
		// exporter is disabled
		return hubbleExportersOut{}, nil
	}

	exporterFactory := exporter.NewExporterFactory(params.Logger)
	exporterConfigParser := exporter.NewExporterConfigParser(params.Logger)
	dynamicExporter := exporter.NewDynamicExporter(params.Logger, params.Config.FlowlogsConfigFilePath, exporterFactory, exporterConfigParser)
	params.JobGroup.Add(job.OneShot("hubble-dynamic-exporter", func(ctx context.Context, health cell.Health) error {
		return dynamicExporter.Watch(ctx)
	}))
	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			return dynamicExporter.Stop()
		},
	})
	return hubbleExportersOut{Exporters: []exporter.FlowLogExporter{dynamicExporter}}, nil
}
