// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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
