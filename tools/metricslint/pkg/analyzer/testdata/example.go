// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package testdata

type opts struct{}

type metric struct {
	count int
}

func (m *metric) WithLabelValues(lvs ...string) {
	if len(lvs) != m.count {
		panic("inconsistent label cardinality")
	}
}

func newMetricVec(o opts, labels []string) *metric {
	return &metric{
		count: len(labels),
	}
}

type abstractMetric interface {
	WithLabelValues(lvs ...string)
}

type instance struct {
	a abstractMetric
	b abstractMetric
	c abstractMetric
}

func NewInstance() *instance {
	return &instance{
		a: newMetricVec(opts{}, []string{"1"}),
		b: newMetricVec(opts{}, []string{"1", "2"}),
		c: newMetricVec(opts{}, []string{"1", "2", "3"}),
	}
}

func main() {
	i := NewInstance()

	i.a.WithLabelValues("one")
	i.b.WithLabelValues("one", "two")
	i.c.WithLabelValues("one", "two", "three")

	i.a.WithLabelValues("one", "two")          // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'a'; want: 1, got: 2`
	i.b.WithLabelValues("one")                 // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'b'; want: 2, got: 1`
	i.b.WithLabelValues("one", "two", "three") // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'b'; want: 2, got: 3`
	i.c.WithLabelValues("one")                 // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'c'; want: 3, got: 1`
	i.c.WithLabelValues("one", "two")          // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'c'; want: 3, got: 2`

	values := []string{"uno", "dos", "tres"}
	i.a.WithLabelValues(values...) // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'a'; want: 1, got: 3`
	i.b.WithLabelValues(values...) // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'b'; want: 2, got: 3`

	newValues := []string{"一", "二", "三"}
	nestedObj := struct {
		inner []string
	}{
		inner: newValues,
	}
	i.a.WithLabelValues(nestedObj.inner...) // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'a'; want: 1, got: 3`
	i.b.WithLabelValues(nestedObj.inner...) // want `Method 'WithLabelValues' should have equal parameter count to call 'newMetricVec' which initializes 'b'; want: 2, got: 3`
}
