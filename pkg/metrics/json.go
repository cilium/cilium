// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

type JSONSampleDump struct {
	NumSamples      int           `json:"nsamples" yaml:"nsamples"`
	IntervalSeconds int           `json:"interval_seconds" yaml:"interval_seconds"`
	Samples         []JSONSamples `json:"samples" yaml:"samples"`
}

type JSONGaugeOrCounter struct {
	Samples []float32 `json:"samples,omitempty" yaml:"samples,omitempty"`
}

type JSONHistogram struct {
	P50 []float32 `json:"p50,omitempty" yaml:"p50,omitempty"`
	P90 []float32 `json:"p90,omitempty" yaml:"p90,omitempty"`
	P99 []float32 `json:"p99,omitempty" yaml:"p99,omitempty"`
}

type JSONSamples struct {
	Name           string              `json:"name" yaml:"name"`
	Labels         string              `json:"labels,omitempty" yaml:"labels,omitempty"`
	GaugeOrCounter *JSONGaugeOrCounter `json:"gaugeOrCounter,omitempty" yaml:"gaugeOrCounter,omitempty"`
	Histogram      *JSONHistogram      `json:"histogram,omitempty" yaml:"histogram,omitempty"`
	Latest         string              `json:"latest" yaml:"latest"`
}
