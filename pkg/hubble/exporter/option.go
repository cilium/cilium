// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"log/slog"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
)

// DefaultOptions specifies default values for Hubble exporter options.
var DefaultOptions = Options{
	newWriterFunc:  StdoutNoOpWriter,
	newEncoderFunc: JsonEncoder,
}

// Options stores all the configurations values for Hubble exporter.
type Options struct {
	AllowList, DenyList []*flowpb.FlowFilter
	FieldMask           fieldmask.FieldMask
	OnExportEvent       []OnExportEvent

	// keep types that can't be marshalled as JSON private
	newWriterFunc             NewWriterFunc
	newEncoderFunc            NewEncoderFunc
	allowFilters, denyFilters filters.FilterFuncs
}

// Option customizes the configuration of the hubble server.
type Option func(o *Options) error

// WithNewWriterFunc sets the constructor function for the export event writer.
func WithNewWriterFunc(newWriterFunc NewWriterFunc) Option {
	return func(o *Options) error {
		o.newWriterFunc = newWriterFunc
		return nil
	}
}

// WithNewEncoderFunc sets the constructor function for the exporter encoder.
func WithNewEncoderFunc(newEncoderFunc NewEncoderFunc) Option {
	return func(o *Options) error {
		o.newEncoderFunc = newEncoderFunc
		return nil
	}
}

// WithAllowListFilter sets allowlist filter for the exporter.
func WithAllowList(log *slog.Logger, f []*flowpb.FlowFilter) Option {
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
func WithDenyList(log *slog.Logger, f []*flowpb.FlowFilter) Option {
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

func (o *Options) NewWriterFunc() NewWriterFunc {
	return o.newWriterFunc
}

func (o *Options) NewEncoderFunc() NewEncoderFunc {
	return o.newEncoderFunc
}
