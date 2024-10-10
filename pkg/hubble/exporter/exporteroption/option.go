// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporteroption

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
)

// Options stores all the configurations values for Hubble exporter.
type Options struct {
	Path       string
	MaxSizeMB  int
	MaxBackups int
	Compress   bool

	AllowList, DenyList []*flowpb.FlowFilter
	FieldMask           fieldmask.FieldMask

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

func (o *Options) AllowFilters() filters.FilterFuncs {
	return o.allowFilters
}

func (o *Options) DenyFilters() filters.FilterFuncs {
	return o.denyFilters
}
