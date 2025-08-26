// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestGaugeWithLabels(t *testing.T) {
	o := NewGaugeVecWithLabels(GaugeOpts{
		Namespace: "cilium",
		Subsystem: "subsystem",
		Name:      "test",
	}, Labels{
		{Name: "foo", Values: NewValues("0", "1")},
		{Name: "bar", Values: NewValues("a", "b")},
	})
	r := prometheus.NewRegistry()
	r.MustRegister(o)
	ms, err := dumpMetrics(o)
	assert.NoError(t, err)
	assert.Len(t, ms, 4)
}
