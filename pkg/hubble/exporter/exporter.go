// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cilium/lumberjack/v2"
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// exporter is an implementation of OnDecodedEvent interface that writes Hubble events to a file.
type exporter struct {
	logger  logrus.FieldLogger
	encoder *json.Encoder
}

// NewExporter initializes an exporter.
func NewExporter(
	logger logrus.FieldLogger,
	options ...exporteroption.Option) (*exporter, error) {
	opts := exporteroption.Default // start with defaults
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	logger.WithField("options", opts).Info("Configuring Hubble event exporter")
	encoder := json.NewEncoder(&lumberjack.Logger{
		Filename:   opts.Path,
		MaxSize:    opts.MaxSizeMB,
		MaxBackups: opts.MaxBackups,
		Compress:   opts.Compress,
	})
	return newExporter(logger, encoder), nil
}

func newExporter(logger logrus.FieldLogger, encoder *json.Encoder) *exporter {
	return &exporter{
		logger:  logger,
		encoder: encoder,
	}
}

// eventToExportEvent converts Event to ExportEvent.
func eventToExportEvent(e *v1.Event) *observerpb.ExportEvent {
	switch ev := e.Event.(type) {
	case *flowpb.Flow:
		return &observerpb.ExportEvent{
			Time:     ev.GetTime(),
			NodeName: ev.GetNodeName(),
			ResponseTypes: &observerpb.ExportEvent_Flow{
				Flow: ev,
			},
		}
	case *flowpb.LostEvent:
		return &observerpb.ExportEvent{
			Time:     e.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_LostEvents{
				LostEvents: ev,
			},
		}
	case *flowpb.AgentEvent:
		return &observerpb.ExportEvent{
			Time:     e.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_AgentEvent{
				AgentEvent: ev,
			},
		}
	case *flowpb.DebugEvent:
		return &observerpb.ExportEvent{
			Time:     e.Timestamp,
			NodeName: nodeTypes.GetName(),
			ResponseTypes: &observerpb.ExportEvent_DebugEvent{
				DebugEvent: ev,
			},
		}
	default:
		return nil
	}
}

// Start calls GetFlows and writes responses to a file.
func (e *exporter) OnDecodedEvent(_ context.Context, ev *v1.Event) (bool, error) {
	res := eventToExportEvent(ev)
	if res == nil {
		return false, nil
	}
	return false, e.encoder.Encode(res)
}
