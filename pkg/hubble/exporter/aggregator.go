// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"log/slog"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
	fa "github.com/cilium/cilium/pkg/hubble/parser/fieldaggregate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AggregateKey represents a combination of field values used for aggregation.
type AggregateKey string

// AggregateValue holds the counters for ingress, egress, and unknown direction flows.
type AggregateValue struct {
	IngressFlowCount          int
	EgressFlowCount           int
	UnknownDirectionFlowCount int
	ProcessedFlow             *ir.Flow
}

type Aggregator struct {
	m              map[AggregateKey]*AggregateValue
	mu             lock.RWMutex
	fieldAggregate fa.FieldAggregate
	logger         *slog.Logger
}

// NewAggregator creates a new aggregator without field aggregation.
func NewAggregator(logger *slog.Logger) *Aggregator {
	return &Aggregator{
		m:      make(map[AggregateKey]*AggregateValue),
		logger: logger.With(logfields.LogSubsys, "hubble-aggregator"),
	}
}

// NewAggregatorWithFields creates a new aggregator with field aggregation.
func NewAggregatorWithFields(fieldAggregate fa.FieldAggregate, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		m:              make(map[AggregateKey]*AggregateValue),
		fieldAggregate: fieldAggregate,
		logger:         logger.With(logfields.LogSubsys, "hubble-aggregator"),
	}
}

func (a *Aggregator) Add(ev *v1.Event) {
	if ev == nil {
		return
	}
	f := ev.GetFlow()
	if f == nil {
		return
	}

	processedFlow := new(flowpb.Flow)
	a.fieldAggregate.Copy(processedFlow.ProtoReflect(), f.ToProto().ProtoReflect())

	// Enrich the processed flow with timestamp after key generation.
	// This ensures timestamp doesn't affect aggregation, but preserves temporal context.
	processedFlow.Time = ev.Timestamp
	k := generateAggregationKey(processedFlow)

	a.mu.Lock()
	defer a.mu.Unlock()

	if v, ok := a.m[k]; ok {
		switch f.TrafficDirection {
		case flowpb.TrafficDirection_INGRESS:
			v.IngressFlowCount++
		case flowpb.TrafficDirection_EGRESS:
			v.EgressFlowCount++
		default:
			v.UnknownDirectionFlowCount++
		}
		return
	}

	var v AggregateValue
	switch f.TrafficDirection {
	case flowpb.TrafficDirection_INGRESS:
		v = AggregateValue{
			IngressFlowCount: 1,
			ProcessedFlow:    f,
		}
	case flowpb.TrafficDirection_EGRESS:
		v = AggregateValue{
			EgressFlowCount: 1,
			ProcessedFlow:   f,
		}
	default:
		v = AggregateValue{
			UnknownDirectionFlowCount: 1,
			ProcessedFlow:             f,
		}
	}
	a.m[k] = &v
}

// Export exports all aggregated flows and clears the aggregator.
func (a *Aggregator) Export(encoder Encoder) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, value := range a.m {
		exportEvent := processedFlowToAggregatedExportEvent(value.ProcessedFlow, value.IngressFlowCount, value.EgressFlowCount, value.UnknownDirectionFlowCount)
		if exportEvent == nil {
			continue
		}

		if err := encoder.Encode(exportEvent); err != nil {
			a.logger.Error("Failed to export aggregate", logfields.Error, err)
		}
	}

	if a.m == nil {
		a.m = make(map[AggregateKey]*AggregateValue)
		return
	}
	for k := range a.m {
		delete(a.m, k)
	}
}

func generateAggregationKey(processedFlow *flowpb.Flow) AggregateKey {
	b, _ := proto.Marshal(processedFlow.ProtoReflect().Interface())

	return AggregateKey(b)
}

// AggregatorRunner manages the lifecycle of an aggregator with periodic export.
type AggregatorRunner struct {
	aggregator *Aggregator
	interval   time.Duration
	encoder    Encoder
	logger     *slog.Logger

	stop chan struct{}
	wg   sync.WaitGroup
}

func (r *AggregatorRunner) Start() {
	if r.stop != nil {
		r.logger.Error("AggregatorRunner is already started.")
		return
	}
	r.stop = make(chan struct{})
	r.wg.Add(1)
	go r.run()
}

func (r *AggregatorRunner) Stop() {
	if r.stop != nil {
		close(r.stop)
	}
	r.wg.Wait()
	r.stop = nil
}

func (r *AggregatorRunner) Add(event *v1.Event) {
	r.aggregator.Add(event)
}

func (r *AggregatorRunner) run() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)

	for {
		select {
		case <-r.stop:
			// Flush before stopping.
			r.exportAggregates()
			return
		case <-ticker.C:
			r.exportAggregates()
		}
	}
}

func (r *AggregatorRunner) exportAggregates() {
	r.aggregator.Export(r.encoder)
}

// processedFlowToAggregatedExportEvent converts a flow to ExportEvent with aggregation counts.
func processedFlowToAggregatedExportEvent(processedFlow *ir.Flow, ingressCount, egressCount, unknownDirectionFlowCount int) *observerpb.ExportEvent {
	flow := processedFlow.ToProto()
	flow.Aggregate = &flowpb.Aggregate{
		IngressFlowCount:          uint32(ingressCount),
		EgressFlowCount:           uint32(egressCount),
		UnknownDirectionFlowCount: uint32(unknownDirectionFlowCount),
	}

	return &observerpb.ExportEvent{
		Time:     timestamppb.New(processedFlow.Time),
		NodeName: processedFlow.NodeName,
		ResponseTypes: &observerpb.ExportEvent_Flow{
			Flow: flow,
		},
	}
}
