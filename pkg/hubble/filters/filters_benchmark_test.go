// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

var (
	matchingEvent    = &v1.Event{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 20222, DestinationPort: 80}}}}}
	nonMatchingEvent = &v1.Event{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 30222, DestinationPort: 53}}}}}
)

func runFilterBenchmark(b *testing.B, ff *flowpb.FlowFilter, events []*v1.Event) {
	filterFuncs, err := BuildFilter(b.Context(), ff, DefaultFilters(hivetest.Logger(b)))
	require.NoError(b, err)

	for b.Loop() {
		for _, ev := range events {
			filterFuncs.MatchOne(ev)
		}
	}
}

func duplicateEvent(ev *v1.Event, n int) []*v1.Event {
	evs := make([]*v1.Event, n)
	for i := range n {
		evs[i] = matchingEvent
	}
	return evs
}

func BenchmarkEmptyFlowFilter1(b *testing.B) {
	runFilterBenchmark(b, &flowpb.FlowFilter{}, []*v1.Event{matchingEvent})
}

func BenchmarkEmptyFlowFilter100(b *testing.B) {
	evs := duplicateEvent(matchingEvent, 100)
	runFilterBenchmark(b, &flowpb.FlowFilter{}, evs)
}

var basicL4Filter = &flowpb.FlowFilter{
	Protocol:        []string{"tcp"},
	DestinationPort: []string{"80", "443"},
}

func BenchmarkBasicL4ProtocolPortFlowFilterMatching1(b *testing.B) {
	runFilterBenchmark(b, basicL4Filter, []*v1.Event{matchingEvent})
}

func BenchmarkBasicL4ProtocolPortFlowFilterMatching100(b *testing.B) {
	evs := duplicateEvent(matchingEvent, 100)
	runFilterBenchmark(b, basicL4Filter, evs)
}

func BenchmarkBasicL4ProtocolPortFlowFilterNonMatching1(b *testing.B) {
	runFilterBenchmark(b, basicL4Filter, []*v1.Event{matchingEvent})
}

func BenchmarkBasicL4ProtocolPortFlowFilterNonMatching100(b *testing.B) {
	evs := duplicateEvent(nonMatchingEvent, 100)
	runFilterBenchmark(b, basicL4Filter, evs)
}

var celL4Filter = &flowpb.FlowFilter{
	Experimental: &flowpb.FlowFilter_Experimental{
		CelExpression: []string{"has(_flow.l4.TCP) && (_flow.l4.TCP.destination_port == uint(80) || _flow.l4.TCP.destination_port == uint(443))"},
	},
}

func BenchmarkCELL4ProtocolPortFlowFilterMatching1(b *testing.B) {
	runFilterBenchmark(b, celL4Filter, []*v1.Event{matchingEvent})
}

func BenchmarkCELL4ProtocolPortFlowFilterMatching100(b *testing.B) {
	evs := duplicateEvent(matchingEvent, 100)
	runFilterBenchmark(b, celL4Filter, evs)
}

func BenchmarkCELL4ProtocolPortFlowFilterNonMatching1(b *testing.B) {
	runFilterBenchmark(b, celL4Filter, []*v1.Event{matchingEvent})
}

func BenchmarkCELL4ProtocolPortFlowFilterNonMatching100(b *testing.B) {
	evs := duplicateEvent(nonMatchingEvent, 100)
	runFilterBenchmark(b, celL4Filter, evs)
}

func TestBenchmarkFiltersAreEquivalent(t *testing.T) {
	log := hivetest.Logger(t)
	basicFuncs, err := BuildFilter(t.Context(), basicL4Filter, DefaultFilters(log))
	require.NoError(t, err)
	celFuncs, err := BuildFilter(t.Context(), celL4Filter, DefaultFilters(log))
	require.NoError(t, err)

	gotBasic := basicFuncs.MatchOne(matchingEvent)
	gotCel := celFuncs.MatchOne(matchingEvent)
	assert.Equal(t, gotBasic, gotCel, "expected basic L4 filter and CEL L4 filter to be the same")

	gotBasic = basicFuncs.MatchOne(nonMatchingEvent)
	gotCel = celFuncs.MatchOne(nonMatchingEvent)
	assert.Equal(t, gotBasic, gotCel, "expected basic L4 filter and CEL L4 filter to be the same")
}
