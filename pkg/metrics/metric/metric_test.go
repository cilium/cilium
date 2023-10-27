// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func dumpMetrics(o prometheus.Collector) ([]*dto.Metric, error) {
	ch := make(chan prometheus.Metric)
	done := make(chan any)
	ms := make([]prometheus.Metric, 0)
	go func() {
		for m := range ch {
			ms = append(ms, m)
		}
		close(done)
	}()

	o.Collect(ch)
	close(ch)
	<-done
	mtrcs := make([]*dto.Metric, 0, len(ms))
	for _, m := range ms {
		mtrc := &dto.Metric{}
		if err := m.Write(mtrc); err != nil {
			return nil, err
		}
		mtrcs = append(mtrcs, mtrc)
	}
	return mtrcs, nil
}

func TestLabelsnamesToValues(t *testing.T) {
	ls := &labelSet{
		lbls: Labels{
			{Name: "foo", Values: NewValues("0", "1")},
			{Name: "bar", Values: NewValues("2", "3", "4")},
		},
	}
	ntov := ls.namesToValues()
	assert.Equal(t, map[string]struct{}{
		"0": {},
		"1": {},
	}, ntov["foo"])
	assert.Equal(t, map[string]struct{}{
		"2": {},
		"3": {},
		"4": {},
	}, ntov["bar"])

	assert.NoError(t, ls.checkLabels(map[string]string{
		"foo": "0",
		"bar": "2",
	}))
	assert.Error(t, ls.checkLabels(map[string]string{
		"foo": "bad-val",
		"bar": "2",
	}))
	assert.Error(t, ls.checkLabels(map[string]string{
		"foo": "0",
		"bar": "bad-val",
	}))
	assert.NoError(t, ls.checkLabelValues([]string{"1", "4"}))
	assert.Error(t, ls.checkLabelValues([]string{"bad-val", "2"}))
	assert.Error(t, ls.checkLabelValues([]string{"0", "bad-val"}))
}
