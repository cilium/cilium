// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporteroption

import (
	"context"
	"io"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
)

// NewEncoderFunc is an Encoder constructor.
type NewEncoderFunc func(writer io.Writer) (Encoder, error)

// Encoder provides encoding capabilities for arbitrary data.
type Encoder interface {
	Encode(v any) error
}

// OnExportEvent is a hook that can be registered on an exporter and is invoked for each event.
//
// Returning false will stop the export pipeline for the current event, meaning the default export
// logic as well as the following hooks will not run.
type OnExportEvent interface {
	OnExportEvent(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error)
}

// OnExportEventFunc implements OnExportEvent for a single function.
type OnExportEventFunc func(ctx context.Context, ev *v1.Event, encoder Encoder) (stop bool, err error)

// OnExportEventFunc implements OnExportEvent.
func (f OnExportEventFunc) OnExportEvent(ctx context.Context, ev *v1.Event, encoder Encoder) (bool, error) {
	return f(ctx, ev, encoder)
}

// Options stores all the configurations values for Hubble exporter.
type Options struct {
	Path       string
	MaxSizeMB  int
	MaxBackups int
	Compress   bool

	NewEncoderFunc      NewEncoderFunc
	AllowList, DenyList []*flowpb.FlowFilter
	FieldMask           fieldmask.FieldMask
	OnExportEvent       []OnExportEvent

	allowFilters, denyFilters filters.FilterFuncs
}

// Option customizes the configuration of the hubble server.
type Option func(o *Options) error

// WithPath sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithPath(path string) Option {
	return func(o *Options) error {
		o.Path = path
		return nil
	}
}

// WithMaxSizeMB sets the size in MB at which to rotate the Hubble export file.
func WithMaxSizeMB(size int) Option {
	return func(o *Options) error {
		o.MaxSizeMB = size
		return nil
	}
}

// WithMaxSizeMB sets the number of rotated Hubble export files to keep.
func WithMaxBackups(backups int) Option {
	return func(o *Options) error {
		o.MaxBackups = backups
		return nil
	}
}

// WithCompress specifies whether rotated files are compressed.
func WithCompress() Option {
	return func(o *Options) error {
		o.Compress = true
		return nil
	}
}

// WithNewEncoderFunc sets the constructor function for the exporter encoder.
func WithNewEncoderFunc(newEncoderFunc NewEncoderFunc) Option {
	return func(o *Options) error {
		o.NewEncoderFunc = newEncoderFunc
		return nil
	}
}

// WithAllowListFilter sets allowlist filter for the exporter.
func WithAllowList(log logrus.FieldLogger, f []*flowpb.FlowFilter) Option {
	return func(o *Options) error {
		filterList, err := filters.BuildFilterList(context.Background(), f, filters.DefaultFilters(log))
		if err != nil {
			return err
		}
		o.allowFilters = filterList
		return nil
	}
}

// WithDenyListFilter sets denylist filter for the exporter.
func WithDenyList(log logrus.FieldLogger, f []*flowpb.FlowFilter) Option {
	return func(o *Options) error {
		filterList, err := filters.BuildFilterList(context.Background(), f, filters.DefaultFilters(log))
		if err != nil {
			return err
		}
		o.denyFilters = filterList
		return nil
	}
}

// WithFieldMask sets fieldmask for the exporter.
func WithFieldMask(paths []string) Option {
	return func(o *Options) error {
		fm, err := fieldmaskpb.New(&flowpb.Flow{}, paths...)
		if err != nil {
			return err
		}
		fieldMask, err := fieldmask.New(fm)
		if err != nil {
			return err
		}
		o.FieldMask = fieldMask
		return nil
	}
}

// WithOnExportEvent registers an OnExportEvent hook on the exporter.
func WithOnExportEvent(onExportEvent OnExportEvent) Option {
	return func(o *Options) error {
		o.OnExportEvent = append(o.OnExportEvent, onExportEvent)
		return nil
	}
}

// WithOnExportEventFunc registers an OnExportEventFunc hook on the exporter.
func WithOnExportEventFunc(onExportEventFunc OnExportEventFunc) Option {
	return WithOnExportEvent(onExportEventFunc)
}

func (o *Options) AllowFilters() filters.FilterFuncs {
	return o.allowFilters
}

func (o *Options) DenyFilters() filters.FilterFuncs {
	return o.denyFilters
}
