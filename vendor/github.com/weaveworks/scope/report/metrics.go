package report

import (
	"math"
	"time"

	"github.com/ugorji/go/codec"
)

// Metrics is a string->metric map.
type Metrics map[string]Metric

// Lookup the metric for the given key
func (m Metrics) Lookup(key string) (Metric, bool) {
	v, ok := m[key]
	return v, ok
}

// Merge merges two sets maps into a fresh set, performing set-union merges as
// appropriate.
func (m Metrics) Merge(other Metrics) Metrics {
	result := m.Copy()
	for k, v := range other {
		if rv, ok := result[k]; ok {
			result[k] = rv.Merge(v)
		} else {
			result[k] = v
		}
	}
	return result
}

// Copy returns a value copy of the sets map.
func (m Metrics) Copy() Metrics {
	result := make(Metrics, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// Metric is a list of timeseries data with some metadata. Clients must use the
// Add method to add values.  Metrics are immutable.
type Metric struct {
	Samples     []Sample
	Min, Max    float64
	First, Last time.Time
}

// Sample is a single datapoint of a metric.
type Sample struct {
	Timestamp time.Time `json:"date"`
	Value     float64   `json:"value"`
}

// MakeSingletonMetric makes a metric with a single value
func MakeSingletonMetric(t time.Time, v float64) Metric {
	return Metric{
		Samples: []Sample{{t, v}},
		Min:     v,
		Max:     v,
		First:   t,
		Last:    t,
	}

}

// MakeMetric makes a new Metric from unique samples incrementally ordered in
// time.
func MakeMetric(samples []Sample) Metric {
	if len(samples) < 1 {
		return Metric{}
	}

	var (
		min = samples[0].Value
		max = samples[0].Value
	)

	for i := 1; i < len(samples); i++ {
		if samples[i].Value < min {
			min = samples[i].Value
		} else if samples[i].Value > max {
			max = samples[i].Value
		}
	}

	return Metric{
		Samples: samples,
		Min:     min,
		Max:     max,
		First:   samples[0].Timestamp,
		Last:    samples[len(samples)-1].Timestamp,
	}
}

// WithMax returns a fresh copy of m, with Max set to max
func (m Metric) WithMax(max float64) Metric {
	return Metric{
		Samples: m.Samples,
		Max:     max,
		Min:     m.Min,
		First:   m.First,
		Last:    m.Last,
	}
}

// Len returns the number of samples in the metric.
func (m Metric) Len() int {
	return len(m.Samples)
}

func first(t1, t2 time.Time) time.Time {
	if t2.IsZero() || (!t1.IsZero() && t1.Before(t2)) {
		return t1
	}
	return t2
}

func last(t1, t2 time.Time) time.Time {
	if t2.IsZero() || (!t1.IsZero() && t1.After(t2)) {
		return t1
	}
	return t2
}

// Merge combines the two Metrics and returns a new result.
func (m Metric) Merge(other Metric) Metric {

	// Optimize the empty and non-overlapping case since they are very common
	switch {
	case len(m.Samples) == 0:
		return other
	case len(other.Samples) == 0:
		return m
	case other.First.After(m.Last):
		samplesOut := make([]Sample, len(m.Samples)+len(other.Samples))
		copy(samplesOut, m.Samples)
		copy(samplesOut[len(m.Samples):], other.Samples)
		return Metric{
			Samples: samplesOut,
			Max:     math.Max(m.Max, other.Max),
			Min:     math.Min(m.Min, other.Min),
			First:   m.First,
			Last:    other.Last,
		}
	case m.First.After(other.Last):
		samplesOut := make([]Sample, len(m.Samples)+len(other.Samples))
		copy(samplesOut, other.Samples)
		copy(samplesOut[len(other.Samples):], m.Samples)
		return Metric{
			Samples: samplesOut,
			Max:     math.Max(m.Max, other.Max),
			Min:     math.Min(m.Min, other.Min),
			First:   other.First,
			Last:    m.Last,
		}
	}

	// Merge two lists of Samples in O(n)
	samplesOut := make([]Sample, 0, len(m.Samples)+len(other.Samples))
	mI, otherI := 0, 0
	for {
		if otherI >= len(other.Samples) {
			samplesOut = append(samplesOut, m.Samples[mI:]...)
			break
		} else if mI >= len(m.Samples) {
			samplesOut = append(samplesOut, other.Samples[otherI:]...)
			break
		}

		if m.Samples[mI].Timestamp.Equal(other.Samples[otherI].Timestamp) {
			samplesOut = append(samplesOut, m.Samples[mI])
			mI++
			otherI++
		} else if m.Samples[mI].Timestamp.Before(other.Samples[otherI].Timestamp) {
			samplesOut = append(samplesOut, m.Samples[mI])
			mI++
		} else {
			samplesOut = append(samplesOut, other.Samples[otherI])
			otherI++
		}
	}

	return Metric{
		Samples: samplesOut,
		Max:     math.Max(m.Max, other.Max),
		Min:     math.Min(m.Min, other.Min),
		First:   first(m.First, other.First),
		Last:    last(m.Last, other.Last),
	}
}

// Div returns a new copy of the metric, with each value divided by n.
func (m Metric) Div(n float64) Metric {
	samplesOut := make([]Sample, len(m.Samples), len(m.Samples))

	for i := range m.Samples {
		samplesOut[i].Value = m.Samples[i].Value / n
		samplesOut[i].Timestamp = m.Samples[i].Timestamp
	}
	return Metric{
		Samples: samplesOut,
		Max:     m.Max / n,
		Min:     m.Min / n,
		First:   m.First,
		Last:    m.Last,
	}
}

// LastSample obtains the last sample of the metric
func (m Metric) LastSample() (Sample, bool) {
	if m.Samples == nil {
		return Sample{}, false
	}
	return m.Samples[len(m.Samples)-1], true
}

// WireMetrics is the on-the-wire representation of Metrics.
// Only needed for backwards compatibility with probes
// (time.Time is encoded in binary in MsgPack)
type WireMetrics struct {
	Samples []Sample `json:"samples,omitempty"`
	Min     float64  `json:"min"`
	Max     float64  `json:"max"`
	First   string   `json:"first,omitempty"`
	Last    string   `json:"last,omitempty"`
}

func renderTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// ToIntermediate converts the metric to a representation suitable
// for serialization.
func (m Metric) ToIntermediate() WireMetrics {
	return WireMetrics{
		Samples: m.Samples,
		Max:     m.Max,
		Min:     m.Min,
		First:   renderTime(m.First),
		Last:    renderTime(m.Last),
	}
}

// FromIntermediate obtains the metric from a representation suitable
// for serialization.
func (m WireMetrics) FromIntermediate() Metric {
	return Metric{
		Samples: m.Samples,
		Max:     m.Max,
		Min:     m.Min,
		First:   parseTime(m.First),
		Last:    parseTime(m.Last),
	}
}

// CodecEncodeSelf implements codec.Selfer
func (m *Metric) CodecEncodeSelf(encoder *codec.Encoder) {
	in := m.ToIntermediate()
	encoder.Encode(in)
}

// CodecDecodeSelf implements codec.Selfer
func (m *Metric) CodecDecodeSelf(decoder *codec.Decoder) {
	in := WireMetrics{}
	if err := decoder.Decode(&in); err != nil {
		return
	}
	*m = in.FromIntermediate()
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead
func (Metric) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead
func (*Metric) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}
