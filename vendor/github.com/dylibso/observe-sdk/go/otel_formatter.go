package observe

import (
	"encoding/binary"
	"encoding/hex"
	"time"

	common "go.opentelemetry.io/proto/otlp/common/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	trace "go.opentelemetry.io/proto/otlp/trace/v1"
)

type OtelTrace struct {
	TraceId    string
	TracesData *trace.TracesData
}

func NewOtelTrace(traceId string, serviceName string, spans []*trace.Span) *OtelTrace {
	return &OtelTrace{
		TraceId: traceId,
		TracesData: &trace.TracesData{
			ResourceSpans: []*trace.ResourceSpans{
				{
					Resource: &resource.Resource{
						Attributes: []*common.KeyValue{
							NewOtelKeyValueString("service.name", serviceName),
						},
					},
					ScopeSpans: []*trace.ScopeSpans{
						{
							Spans: spans,
						},
					},
				},
			},
		},
	}
}

func (t *OtelTrace) SetMetadata(te *TraceEvent, meta map[string]string) {
	for _, rs := range t.TracesData.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				for key, value := range meta {
					span.Attributes = append(span.Attributes, NewOtelKeyValueString(key, value))
				}
			}
		}
	}
}

func NewOtelSpan(traceId string, parentId []byte, name string, start, end time.Time) *trace.Span {
	if parentId == nil {
		parentId = []byte{}
	}

	traceIdB, err := hex.DecodeString(traceId)
	if err != nil {
		panic(err)
	}

	spanId := NewSpanId().Msb()
	spanIdB := make([]byte, 8)
	binary.LittleEndian.PutUint64(spanIdB, spanId)

	return &trace.Span{
		TraceId:           traceIdB,
		SpanId:            spanIdB,
		ParentSpanId:      parentId,
		Name:              name,
		Kind:              1,
		StartTimeUnixNano: uint64(start.UnixNano()),
		EndTimeUnixNano:   uint64(end.UnixNano()),
		// uses empty defaults for remaining fields...
	}
}

func NewOtelKeyValueString(key string, value string) *common.KeyValue {
	strVal := &common.AnyValue_StringValue{
		StringValue: value,
	}
	return &common.KeyValue{
		Key: key,
		Value: &common.AnyValue{
			Value: strVal,
		},
	}
}

func NewOtelKeyValueInt64(key string, value int64) *common.KeyValue {
	intVal := &common.AnyValue_IntValue{
		IntValue: value,
	}
	return &common.KeyValue{
		Key: key,
		Value: &common.AnyValue{
			Value: intVal,
		},
	}
}

func GetOtelAttrFromSpan(attr string, span *trace.Span) (int, *common.KeyValue) {
	for i, attr := range span.Attributes {
		if attr.Key == "allocation" {
			return i, attr
		}
	}
	return -1, nil
}

func AddOtelKeyValueInt64(kvs ...*common.KeyValue) *common.KeyValue {
	if len(kvs) > 0 {
		retKv := &common.KeyValue{
			Key:   kvs[0].Key,
			Value: kvs[0].Value,
		}
		for i := 1; i < len(kvs); i++ {
			v, ok := retKv.Value.Value.(*common.AnyValue_IntValue)
			if ok {
				curr, ok := kvs[i].Value.Value.(*common.AnyValue_IntValue)
				if ok {
					intVal := &common.AnyValue_IntValue{
						IntValue: v.IntValue + curr.IntValue,
					}
					retKv.Value.Value = intVal
				}
			}
		}
		return retKv
	}
	return nil
}
