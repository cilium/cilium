// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"

	"sigs.k8s.io/yaml"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var _ ExporterConfigParser = (*exporterConfigParser)(nil)

type exporterConfigParser struct {
	logger *slog.Logger
}

// NewExporterConfigParser is an ExporterConfig parser for DynamicExportersConfig.
func NewExporterConfigParser(logger *slog.Logger) *exporterConfigParser {
	return &exporterConfigParser{logger}
}

// Parse implements ExporterConfigParser.
func (e *exporterConfigParser) Parse(r io.Reader) (map[string]ExporterConfig, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	var config DynamicExportersConfig
	if err := yaml.Unmarshal(buf.Bytes(), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}
	configs := make(map[string]ExporterConfig, len(config.FlowLogs))
	for _, fl := range config.FlowLogs {
		configs[fl.Name] = fl
	}
	return configs, nil
}

var _ ExporterFactory = (*exporterFactory)(nil)

type exporterFactory struct {
	logger *slog.Logger
}

// NewExporterFactory is a FlowLogExporter factory for FlowLogConfig.
func NewExporterFactory(logger *slog.Logger) *exporterFactory {
	return &exporterFactory{logger}
}

// Create implements ExporterFactory.
func (f *exporterFactory) Create(config ExporterConfig) (FlowLogExporter, error) {
	if config, ok := config.(*FlowLogConfig); ok {
		return f.create(config)
	}
	return nil, fmt.Errorf("invalid config type %T (%+v)", config, config)
}

func (f *exporterFactory) create(config *FlowLogConfig) (*exporter, error) {
	exporterOpts := []Option{
		WithAllowList(f.logger, config.IncludeFilters),
		WithDenyList(f.logger, config.ExcludeFilters),
		WithFieldMask(config.FieldMask),
		WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event, encoder Encoder) (bool, error) {
			stop := !config.IsActive()
			return stop, nil
		}),
	}
	if config.FilePath != "stdout" {
		fileMaxSizeMB := config.FileMaxSizeMB
		if fileMaxSizeMB == 0 {
			fileMaxSizeMB = DefaultFileMaxSizeMB
		}
		fileMaxBackups := config.FileMaxBackups
		if fileMaxBackups == 0 {
			fileMaxBackups = DefaultFileMaxBackups
		}
		exporterOpts = append(exporterOpts, WithNewWriterFunc(FileWriter(FileWriterConfig{
			Filename:   config.FilePath,
			MaxSize:    fileMaxSizeMB,
			MaxBackups: fileMaxBackups,
			Compress:   config.FileCompress,
		})))
	}
	return NewExporter(f.logger.With(logfields.FlowLogName, config.Name), exporterOpts...)
}

// DynamicExportersConfig represents the dynamic hubble exporter configuration file.
type DynamicExportersConfig struct {
	FlowLogs []*FlowLogConfig `json:"flowLogs,omitempty" yaml:"flowLogs,omitempty"`
}

func (c *DynamicExportersConfig) Validate() error {
	flowlogNames := make(map[string]struct{}, len(c.FlowLogs))
	flowlogPaths := make(map[string]struct{}, len(c.FlowLogs))

	var errs error

	for i := range c.FlowLogs {
		if c.FlowLogs[i] == nil {
			errs = errors.Join(errs, fmt.Errorf("invalid flowlog at index %d", i))
			continue
		}
		name := c.FlowLogs[i].Name
		if name == "" {
			errs = errors.Join(errs, fmt.Errorf("name is required"))
		} else {
			if _, ok := flowlogNames[name]; ok {
				errs = errors.Join(errs, fmt.Errorf("duplicated flowlog name %s", name))
			}
			flowlogNames[name] = struct{}{}
		}

		filePath := c.FlowLogs[i].FilePath
		if filePath == "" {
			errs = errors.Join(errs, fmt.Errorf("filePath is required"))
		} else {
			if _, ok := flowlogPaths[filePath]; ok {
				errs = errors.Join(errs, fmt.Errorf("duplicated flowlog path %s", filePath))
			}
			flowlogPaths[filePath] = struct{}{}
		}
	}

	return errs
}

var _ ExporterConfig = (*FlowLogConfig)(nil)

// FlowLogConfig represents configuration of single dynamic exporter.
type FlowLogConfig struct {
	Name           string      `json:"name,omitempty" yaml:"name,omitempty"`
	FilePath       string      `json:"filePath,omitempty" yaml:"filePath,omitempty"`
	FieldMask      FieldMask   `json:"fieldMask,omitempty" yaml:"fieldMask,omitempty"`
	IncludeFilters FlowFilters `json:"includeFilters,omitempty" yaml:"includeFilters,omitempty"`
	ExcludeFilters FlowFilters `json:"excludeFilters,omitempty" yaml:"excludeFilters,omitempty"`
	FileMaxSizeMB  int         `json:"fileMaxSizeMb,omitempty" yaml:"fileMaxSizeMb,omitempty"`
	FileMaxBackups int         `json:"fileMaxBackups,omitempty" yaml:"fileMaxBackups,omitempty"`
	FileCompress   bool        `json:"fileCompress,omitempty" yaml:"fileCompress,omitempty"`
	End            *time.Time  `json:"end,omitempty" yaml:"end,omitempty"`
}

// Equal implements ExporterConfig.
func (f *FlowLogConfig) Equal(other any) bool {
	if other, ok := other.(*FlowLogConfig); ok {
		return f.equals(other)
	}
	return false
}

// Equal implements ExporterConfig.
func (f *FlowLogConfig) IsActive() bool {
	return f.End == nil || f.End.After(time.Now())
}

func (f *FlowLogConfig) equals(other *FlowLogConfig) bool {
	if f == nil && other == nil {
		return true
	}
	if f == nil || other == nil {
		return false
	}

	if f.FilePath != other.FilePath {
		return false
	}

	if !f.FieldMask.equals(other.FieldMask) {
		return false
	}

	if !f.IncludeFilters.equals(other.IncludeFilters) {
		return false
	}

	if !f.ExcludeFilters.equals(other.ExcludeFilters) {
		return false
	}

	if f.FileMaxSizeMB != other.FileMaxSizeMB {
		return false
	}

	if f.FileMaxBackups != other.FileMaxBackups {
		return false
	}

	if f.FileCompress != other.FileCompress {
		return false
	}

	if f.End == nil && other.End != nil ||
		f.End != nil && other.End == nil ||
		f.End != nil && other.End != nil && !f.End.Equal(*other.End) {
		return false
	}

	return true
}

// FlowFilters is a slice of filters to include or exclude flows.
type FlowFilters []*flowpb.FlowFilter

func (f FlowFilters) equals(other FlowFilters) bool {
	aFiltersSet := make(map[string]bool, len(f))
	bFiltersSet := make(map[string]bool, len(other))

	for _, filter := range f {
		aFiltersSet[filter.String()] = true
	}
	for _, filter := range other {
		bFiltersSet[filter.String()] = true
	}
	return reflect.DeepEqual(aFiltersSet, bFiltersSet)
}

// FieldMask is a slice of fields that are included in output.
type FieldMask []string

func (f FieldMask) equals(other FieldMask) bool {
	xs := make([]string, len(f))
	ys := make([]string, len(other))
	copy(xs, f)
	copy(ys, other)
	slices.Sort(xs)
	slices.Sort(ys)
	return reflect.DeepEqual(xs, ys)
}
