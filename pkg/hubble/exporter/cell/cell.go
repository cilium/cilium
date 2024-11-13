// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package exportercell

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
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
	ExportAllowlist []*flowpb.FlowFilter `mapstructure:"hubble-export-allowlist"`
	// ExportDenylist specifies deny list filter use by exporter.
	ExportDenylist []*flowpb.FlowFilter `mapstructure:"hubble-export-denylist"`
	// ExportFieldmask specifies list of fields to log in exporter.
	ExportFieldmask []string `mapstructure:"hubble-export-fieldmask"`
}

var DefaultConfig = config{
	FlowlogsConfigFilePath: "",
	ExportFilePath:         exporteroption.Default.Path,
	ExportFileMaxSizeMB:    exporteroption.Default.MaxSizeMB,
	ExportFileMaxBackups:   exporteroption.Default.MaxBackups,
	ExportFileCompress:     exporteroption.Default.Compress,
	ExportAllowlist:        []*flowpb.FlowFilter{},
	ExportDenylist:         []*flowpb.FlowFilter{},
	ExportFieldmask:        []string{},
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.String("hubble-flowlogs-config-path", def.FlowlogsConfigFilePath, "Filepath with configuration of hubble flowlogs")
	flags.String("hubble-export-file-path", def.ExportFilePath, "Filepath to write Hubble events to. By specifying `stdout` the flows are logged instead of written to a rotated file.")
	flags.Int("hubble-export-file-max-size-mb", def.ExportFileMaxSizeMB, "Size in MB at which to rotate Hubble export file.")
	flags.Int("hubble-export-file-max-backups", def.ExportFileMaxBackups, "Number of rotated Hubble export files to keep.")
	flags.Bool("hubble-export-file-compress", def.ExportFileCompress, "Compress rotated Hubble export files.")
	flags.StringSlice("hubble-export-allowlist", []string{}, "Specify allowlist as JSON encoded FlowFilters to Hubble exporter.")
	flags.StringSlice("hubble-export-denylist", []string{}, "Specify denylist as JSON encoded FlowFilters to Hubble exporter.")
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

type hubbleExportersOut struct {
	cell.Out

	ObserverOptions []observeroption.Option `group:"hubble-observer-options,flatten"`
}

type hubbleExportersParams struct {
	cell.In

	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Config    validatedConfig

	// TODO: replace by slog
	Logger logrus.FieldLogger
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

	exporterOpts := []exporteroption.Option{
		exporteroption.WithPath(params.Config.ExportFilePath),
		exporteroption.WithMaxSizeMB(params.Config.ExportFileMaxSizeMB),
		exporteroption.WithMaxBackups(params.Config.ExportFileMaxBackups),
		exporteroption.WithAllowList(params.Logger, params.Config.ExportAllowlist),
		exporteroption.WithDenyList(params.Logger, params.Config.ExportDenylist),
		exporteroption.WithFieldMask(params.Config.ExportFieldmask),
	}
	if params.Config.ExportFileCompress {
		exporterOpts = append(exporterOpts, exporteroption.WithCompress())
	}
	exporter, err := exporter.NewExporter(params.Logger, exporterOpts...)
	if err != nil {
		// non-fatal failure, log and continue
		params.Logger.WithError(err).Error("Failed to configure Hubble static exporter")
		return hubbleExportersOut{}, nil
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			return exporter.Stop()
		},
	})
	return hubbleExportersOut{
		ObserverOptions: []observeroption.Option{observeroption.WithOnDecodedEvent(exporter)},
	}, nil
}

func NewHubbleDynamicExporter(params hubbleExportersParams) (hubbleExportersOut, error) {
	if params.Config.FlowlogsConfigFilePath == "" {
		// exporter is disabled
		return hubbleExportersOut{}, nil
	}

	exporter := exporter.NewDynamicExporter(params.Logger, params.Config.FlowlogsConfigFilePath, params.Config.ExportFileMaxSizeMB, params.Config.ExportFileMaxBackups)
	params.JobGroup.Add(job.OneShot("hubble-dynamic-exporter", func(ctx context.Context, health cell.Health) error {
		return exporter.Watch(ctx)
	}))
	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			return exporter.Stop()
		},
	})
	return hubbleExportersOut{
		ObserverOptions: []observeroption.Option{observeroption.WithOnDecodedEvent(exporter)},
	}, nil
}
