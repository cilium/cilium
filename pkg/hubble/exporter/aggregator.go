package exporter

import (
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	fa "github.com/cilium/cilium/pkg/hubble/parser/fieldaggregate"
	"github.com/cilium/cilium/pkg/lock"
	"google.golang.org/protobuf/proto"
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
	logger         logrus.FieldLogger
}

func NewAggregator() *Aggregator {
	a := &Aggregator{
		m:      make(map[AggregateKey]*AggregateValue),
		logger: logrus.WithField("subsystem", "hubble-aggregator"),
	}
	return a
}

func NewAggregatorWithFields(fieldAggregate fa.FieldAggregate) *Aggregator {
	a := &Aggregator{
		m:              make(map[AggregateKey]*AggregateValue),
		fieldAggregate: fieldAggregate,
		logger:         logrus.WithField("subsystem", "hubble-aggregator"),
	}
	return a
}

// Add processes an event directly into the aggregation map
func (a *Aggregator) Add(ev *v1.Event) {
	f := ev.GetFlow()
	if f == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Create processed flow with only selected fields
	processedFlow := &flowpb.Flow{}
	a.fieldAggregate.Copy(processedFlow.ProtoReflect(), f.ProtoReflect())

	// Generate key using the already processed flow
	k := a.generateAggregationKey(processedFlow)

	v, ok := a.m[k]
	// Add new entry
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
		default: // TRAFFIC_DIRECTION_UNKNOWN or any other value
			v = &AggregateValue{
				UnknownDirectionFlowCount: 1,
				ProcessedFlow:             processedFlow,
			}
		}
		a.m[k] = v
	} else { // Update existing entry
		switch f.GetTrafficDirection() {
		case flowpb.TrafficDirection_INGRESS:
			v.IngressFlowCount++
		case flowpb.TrafficDirection_EGRESS:
			v.EgressFlowCount++
		default: // TRAFFIC_DIRECTION_UNKNOWN or any other value
			v.UnknownDirectionFlowCount++
		}
	}
}

func (a *Aggregator) generateAggregationKey(processedFlow *flowpb.Flow) AggregateKey {
	b, _ := proto.Marshal(processedFlow.ProtoReflect().Interface())
	return AggregateKey(b)
}
