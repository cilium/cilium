// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"log/slog"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	aggregatepb "github.com/cilium/cilium/api/v1/aggregate"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	fa "github.com/cilium/cilium/pkg/hubble/parser/fieldaggregate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AggregateKey represents a combination of field values used for aggregation
type AggregateKey string

// AggregateValue holds the counters for ingress, egress, and unknown direction flows
type AggregateValue struct {
	IngressFlowCount          int
	EgressFlowCount           int
	UnknownDirectionFlowCount int
	ProcessedFlow             *flowpb.Flow
}

type Aggregator struct {
	m              map[AggregateKey]*AggregateValue
	mu             lock.RWMutex
	fieldAggregate fa.FieldAggregate
	logger         *slog.Logger
}

// NewAggregator creates a new aggregator without field aggregation
func NewAggregator(logger *slog.Logger) *Aggregator {
	return &Aggregator{
		m:      make(map[AggregateKey]*AggregateValue),
		logger: logger.With(logfields.LogSubsys, "hubble-aggregator"),
	}
}

// NewAggregatorWithFields creates a new aggregator with field aggregation
func NewAggregatorWithFields(fieldAggregate fa.FieldAggregate, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		m:              make(map[AggregateKey]*AggregateValue),
		fieldAggregate: fieldAggregate,
		logger:         logger.With(logfields.LogSubsys, "hubble-aggregator"),
	}
}

func (a *Aggregator) Add(ev *v1.Event) {
	f := ev.GetFlow()
	if f == nil {
		return
	}

	processedFlow := &flowpb.Flow{}
	a.fieldAggregate.Copy(processedFlow.ProtoReflect(), f.ProtoReflect())

	k := a.generateAggregationKey(processedFlow)

	a.mu.Lock()
	defer a.mu.Unlock()

	v, ok := a.m[k]
	if !ok {
		switch f.GetTrafficDirection() {
		case flowpb.TrafficDirection_INGRESS:
			v = &AggregateValue{
				IngressFlowCount: 1,
				ProcessedFlow:    processedFlow,
			}
		case flowpb.TrafficDirection_EGRESS:
			v = &AggregateValue{
				EgressFlowCount: 1,
				ProcessedFlow:   processedFlow,
			}
		default:
			v = &AggregateValue{
				UnknownDirectionFlowCount: 1,
				ProcessedFlow:             processedFlow,
			}
		}
		a.m[k] = v
	} else {
		switch f.GetTrafficDirection() {
		case flowpb.TrafficDirection_INGRESS:
			v.IngressFlowCount++
		case flowpb.TrafficDirection_EGRESS:
			v.EgressFlowCount++
		default:
			v.UnknownDirectionFlowCount++
		}
	}
}

func (a *Aggregator) generateAggregationKey(processedFlow *flowpb.Flow) AggregateKey {
	b, _ := proto.Marshal(processedFlow.ProtoReflect().Interface())
	return AggregateKey(b)
}

// AggregatorRunner manages the lifecycle of an aggregator with periodic export
type AggregatorRunner struct {
	aggregator *Aggregator
	interval   time.Duration
	encoder    Encoder
	logger     *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (r *AggregatorRunner) Start(ctx context.Context) {
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go r.run()
}

func (r *AggregatorRunner) Stop() {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.wg.Wait()
}

func (r *AggregatorRunner) Add(event *v1.Event) {
	r.aggregator.Add(event)
}

func (r *AggregatorRunner) run() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			r.exportAggregates()
			return
		case <-ticker.C:
			r.exportAggregates()
		}
	}
}

func (r *AggregatorRunner) exportAggregates() {
	r.aggregator.mu.Lock()
	defer r.aggregator.mu.Unlock()

	for _, value := range r.aggregator.m {
		exportEvent := processedFlowToAggregatedExportEvent(value.ProcessedFlow, value.IngressFlowCount, value.EgressFlowCount, value.UnknownDirectionFlowCount)
		if exportEvent == nil {
			continue
		}

		if err := r.encoder.Encode(exportEvent); err != nil {
			r.logger.Error("Failed to export aggregate", logfields.Error, err)
		}
	}

	r.aggregator.m = make(map[AggregateKey]*AggregateValue)
}

// processedFlowToAggregatedExportEvent converts a flow to ExportEvent with aggregation counts
func processedFlowToAggregatedExportEvent(processedFlow *flowpb.Flow, ingressCount, egressCount, unknownDirectionFlowCount int) *observerpb.ExportEvent {
	aggregate := &aggregatepb.Aggregate{
		IngressFlowCount:          uint32(ingressCount),
		EgressFlowCount:           uint32(egressCount),
		UnknownDirectionFlowCount: uint32(unknownDirectionFlowCount),
	}

	processedFlow.Extensions = toAny(aggregate)

	return &observerpb.ExportEvent{
		Time:     processedFlow.GetTime(),
		NodeName: processedFlow.GetNodeName(),
		ResponseTypes: &observerpb.ExportEvent_Flow{
			Flow: processedFlow,
		},
	}
}

func toAny(message *aggregatepb.Aggregate) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
