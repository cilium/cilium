// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	DefaultFileMaxSizeMB  = 10
	DefaultFileMaxBackups = 5
)

// FlowLogExporter is represents a type that can export hubble events.
type FlowLogExporter interface {
	// Export exports the received event.
	Export(ctx context.Context, ev *v1.Event) error

	// Stop stops this exporter instance from further events processing.
	Stop() error
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

var _ FlowLogExporter = (*exporter)(nil)

// exporter is an implementation of OnDecodedEvent interface that writes Hubble events to a file.
type exporter struct {
	logger  *slog.Logger
	encoder Encoder
	writer  io.WriteCloser
	flow    *flowpb.Flow

	opts Options
}

// NewExporter initializes an
// NOTE: Stopped instances cannot be restarted and should be re-created.
func NewExporter(logger *slog.Logger, options ...Option) (*exporter, error) {
	opts := DefaultOptions // start with defaults
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	logger.Info(
		"Configuring Hubble event exporter",
		logfields.Options, opts,
	)
	return newExporter(logger, opts)
}

// newExporter let's you supply your own WriteCloser for tests.
func newExporter(logger *slog.Logger, opts Options) (*exporter, error) {
	writer, err := opts.NewWriterFunc()()
	if err != nil {
		return nil, fmt.Errorf("failed to create writer: %w", err)
	}
	encoder, err := opts.NewEncoderFunc()(writer)
	if err != nil {
		return nil, fmt.Errorf("failed to create encoder: %w", err)
	}
	var flow *flowpb.Flow
	if opts.FieldMask.Active() {
		flow = new(flowpb.Flow)
		opts.FieldMask.Alloc(flow.ProtoReflect())
	}
	return &exporter{
		logger:  logger,
		encoder: encoder,
		writer:  writer,
		flow:    flow,
		opts:    opts,
	}, nil
}

// Export implements FlowLogExporter.
//
// It takes care of applying filters on the received event, and if allowed, proceeds to invoke the
// registered OnExportEvent hooks. If none of the hooks return true (abort signal) the event is then
// wrapped in observerpb.ExportEvent before being encoded and written to its underlying writer.
func (e *exporter) Export(ctx context.Context, ev *v1.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !filters.Apply(e.opts.AllowFilters(), e.opts.DenyFilters(), ev) {
		return nil
	}

	// Process OnExportEvent hooks
	for _, f := range e.opts.OnExportEvent {
		stop, err := f.OnExportEvent(ctx, ev, e.encoder)
		if err != nil {
			e.logger.Warn("OnExportEvent failed", logfields.Error, err)
		}
		if stop {
			// abort exporter pipeline by returning early but do not prevent
			// other OnDecodedEvent hooks from firing
			return nil
		}
	}

	res := e.eventToExportEvent(ev)
	if res == nil {
		return nil
	}
	return e.encoder.Encode(res)
}

// Stop implements FlowLogExporter.
func (e *exporter) Stop() error {
	e.logger.Debug("hubble flow exporter stopping")
	if e.writer == nil {
		// Already stoppped
		return nil
	}
	err := e.writer.Close()
	e.writer = nil
	return err
}

// eventToExportEvent converts Event to ExportEvent.
func (e *exporter) eventToExportEvent(event *v1.Event) *observerpb.ExportEvent {
	switch ev := event.Event.(type) {
	case *flowpb.Flow:
		if e.opts.FieldMask.Active() {
			e.opts.FieldMask.Copy(e.flow.ProtoReflect(), ev.ProtoReflect())
			ev = e.flow
		}
		return &observerpb.ExportEvent{
			Time:     ev.GetTime(),
			NodeName: ev.GetNodeName(),
			ResponseTypes: &observerpb.ExportEvent_Flow{
				Flow: ev,
			},
		}
	case *flowpb.LostEvent:
		return &observerpb.ExportEvent{
			Time:     event.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_LostEvents{
				LostEvents: ev,
			},
		}
	case *flowpb.AgentEvent:
		return &observerpb.ExportEvent{
			Time:     event.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_AgentEvent{
				AgentEvent: ev,
			},
		}
	case *flowpb.DebugEvent:
		return &observerpb.ExportEvent{
			Time:     event.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_DebugEvent{
				DebugEvent: ev,
			},
		}
	default:
		return nil
	}
}
