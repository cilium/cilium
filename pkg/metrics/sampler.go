// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// sampler periodically samples all metrics (enabled or not).
// The sampled metrics can be inspected with the 'metrics' command.
// 'metrics -s' lists all metrics with samples from the past 2 hours,
// and 'metrics/plot (regex)' plots the matching metric. See files in
// 'testdata/' for examples.
type sampler struct {
	reg              *Registry
	log              *slog.Logger
	mu               lock.Mutex
	metrics          map[metricKey]debugSamples
	maxWarningLogged bool
}

func newSampler(log *slog.Logger, reg *Registry, jg job.Group) *sampler {
	sampler := &sampler{
		log:     log,
		reg:     reg,
		metrics: make(map[metricKey]debugSamples),
	}
	jg.Add(
		job.OneShot("collect", sampler.collectLoop),
		job.Timer("cleanup", sampler.cleanup, metricDeadDuration/2),
	)
	return sampler
}

const (
	// Sample every 5 minutes and keep 2 hours of samples.
	samplingInterval = 5 * time.Minute
	// if you change this, fix m*Index below.
	samplingTimeSpan = 2 * time.Hour
	numSamples       = int(samplingTimeSpan / samplingInterval) // 24 samples
	m30Index         = numSamples/4 - 1
	m60Index         = numSamples/2 - 1
	m120Index        = numSamples - 1

	// Cap the number of metrics we keep around to put an upper limit on memory usage.
	// As there's way fewer histograms than gauges or counters, we can roughly estimate
	// the memory usage as:
	//   max 2000 (20% histo): 400 * sizeof(histogram) + 1600 * sizeof(gaugeOrCounter)
	//                      ~= 400 * 508 + 1600 * 164
	//                      ~= 466kB
	//   worst (100% histo): 2000 * 520 ~= 1MB
	// sizeof(baseSamples) = 24+2*16 = 56
	// sizeof(sampleRing) = 24*4+4 = 100
	// sizeof(histogramSamples): sizeof(baseSamples) + 24+16*8 /* prev */ + 3*sizeof(sampleRing) = 508
	// sizeof(gaugeOrCounterSamples): sizeof(baseSamples) + sizeof(sampleRing) + 8 = 164
	// See also TestSamplerMaxMemoryUsage.
	maxSampledMetrics = 2000

	// The amount of time that has to pass before a sampled metric is considered
	// dead/unregistered. Once passed the sampled data is dropped.
	metricDeadDuration = samplingInterval * time.Duration(numSamples)
)

// metricKey identifies a single metric. We are relying on the fact that
// Desc() always returns by pointer the same Desc.
type metricKey struct {
	desc       *prometheus.Desc
	labelsHash uint64
}

func (k *metricKey) fqName() string {
	// Unfortunately we need to rely on the implementation details of Desc.String()
	// here to extract the name. If it ever changes our tests will catch it.
	// This method is only invoked when the 'metrics' or 'metrics/plot' commands
	// are used, so efficiency is not a huge concern.
	s := k.desc.String()
	const fqNamePrefix = `fqName: "`
	start := strings.Index(s, fqNamePrefix)
	if start < 0 {
		return "???"
	}
	start += len(fqNamePrefix)
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return "???"
	}
	return s[start : start+end]
}

// SampleBitmap tracks which of the 'numSamples' actually exists.
// For histograms we only mark it sampled when the counts have changed.
type SampleBitmap uint64

func (sb *SampleBitmap) mark(b bool) {
	*sb <<= 1
	if b {
		*sb |= 1
	}
}

func (sb SampleBitmap) exists(index int) bool {
	return (sb>>index)&1 == 1
}

type debugSamples interface {
	getName() string
	getLabels() string
	getJSON() JSONSamples

	get() (m5, m30, m60, m120 string)
	getUpdatedAt() time.Time
}

type baseSamples struct {
	updatedAt time.Time
	name      string
	labels    string
}

func (bs baseSamples) getName() string {
	return bs.name
}
func (bs baseSamples) getLabels() string {
	return bs.labels
}

type gaugeOrCounterSamples struct {
	baseSamples

	samples sampleRing

	// pos points to index where the next sample goes.
	// the latest sample is pos-1.
	bits SampleBitmap
}

type sampleRing struct {
	samples [numSamples]float32
	pos     int
}

func (r *sampleRing) push(sample float32) {
	r.samples[r.pos] = sample
	r.pos = (r.pos + 1) % numSamples
}

func (r *sampleRing) grab() []float32 {
	var samples [numSamples]float32
	pos := r.pos - 1
	if pos < 0 {
		pos = numSamples - 1
	}
	for i := range numSamples {
		samples[i] = r.samples[pos]
		pos = pos - 1
		if pos < 0 {
			pos = numSamples - 1
		}
	}
	return samples[:]
}

func (g *gaugeOrCounterSamples) getUpdatedAt() time.Time {
	return g.updatedAt
}

func (g *gaugeOrCounterSamples) getJSON() JSONSamples {
	samples := g.samples.grab()
	return JSONSamples{
		Name:   g.name,
		Labels: g.labels,
		GaugeOrCounter: &JSONGaugeOrCounter{
			Samples: samples[:],
		},
		Latest: prettyValue(float64(samples[0])),
	}
}

func (g *gaugeOrCounterSamples) get() (m1, m30, m60, m120 string) {
	samples := g.samples.grab()
	return prettyValue(float64(samples[0])),
		prettyValue(float64(samples[m30Index])),
		prettyValue(float64(samples[m60Index])),
		prettyValue(float64(samples[m120Index]))
}

type histogramSamples struct {
	baseSamples
	prev          []histogramBucket
	p50, p90, p99 sampleRing
	bits          SampleBitmap
	isSeconds     bool
}

func (h *histogramSamples) get() (m5, m30, m60, m120 string) {
	suffix := ""
	if h.isSeconds {
		suffix = "s"
	}
	pretty := func(p50, p90, p99 float32) string {
		return fmt.Sprintf("%s%s / %s%s / %s%s",
			prettyValue(float64(p50)),
			suffix, prettyValue(float64(p90)),
			suffix, prettyValue(float64(p99)), suffix)
	}
	p50, p90, p99 := h.p50.grab(), h.p90.grab(), h.p99.grab()

	m5 = pretty(p50[0], p90[0], p99[0])
	m30 = pretty(p50[m30Index], p90[m30Index], p99[m30Index])
	m60 = pretty(p50[m60Index], p90[m60Index], p99[m60Index])
	m120 = pretty(p50[m120Index], p90[m120Index], p99[m120Index])
	return
}

func (h *histogramSamples) getUpdatedAt() time.Time {
	return h.updatedAt
}

func (h *histogramSamples) getJSON() JSONSamples {
	p50, p90, p99 := h.p50.grab(), h.p90.grab(), h.p99.grab()
	suffix := ""
	if h.isSeconds {
		suffix = "s"
	}
	return JSONSamples{
		Name:   h.name,
		Labels: h.labels,
		Histogram: &JSONHistogram{
			P50: p50[:],
			P90: p90[:],
			P99: p99[:],
		},
		Latest: fmt.Sprintf("%s%s / %s%s / %s%s",
			prettyValue(float64(p50[0])),
			suffix, prettyValue(float64(p90[0])),
			suffix, prettyValue(float64(p99[0])), suffix),
	}
}

// cleanup runs every hour to remove samples that have not been updated
// in more than an hour (e.g. the metric has been unregistered).
func (dc *sampler) cleanup(ctx context.Context) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	for k, s := range dc.metrics {
		if time.Since(s.getUpdatedAt()) > metricDeadDuration {
			delete(dc.metrics, k)
		}
	}
	return nil
}

func (dc *sampler) collectLoop(ctx context.Context, health cell.Health) error {
	ticker := time.NewTicker(samplingInterval)
	defer ticker.Stop()

	for {
		dc.collect(health)

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (dc *sampler) collect(health cell.Health) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	health.OK("Collecting metrics")

	t0 := time.Now()

	// Since this is meant to have very low overhead we want to avoid heap allocations
	// and other expensive operations as much as possible. Thus we're using Collect()
	// to collect metric one at a time (vs Gather() that does a lot in parallel) and
	// also avoiding building up temporary data structures.
	// One downside of this approach is that we need to parse Desc.String to extract
	// the fqName and the labels, but we do this only when encountering a new metric
	// and tests catch if it ever breaks.

	metricChan := dc.reg.collectors.collect()

	addNewMetric := func(key metricKey, s debugSamples) bool {
		if len(dc.metrics) >= maxSampledMetrics {
			if !dc.maxWarningLogged {
				dc.log.Debug("maximum number of sampled metrics reached")
				dc.maxWarningLogged = true
			}
			return false
		}
		dc.metrics[key] = s
		return true
	}

	numSampled := 0

	for metric := range metricChan {
		var msg dto.Metric
		desc := metric.Desc()
		if err := metric.Write(&msg); err != nil {
			continue
		}
		key := newMetricKey(desc, msg.Label)

		if msg.Histogram != nil {
			var histogram *histogramSamples
			if samples, ok := dc.metrics[key]; !ok {
				name := key.fqName()
				histogram = &histogramSamples{
					baseSamples: baseSamples{name: name, labels: concatLabels(msg.Label)},
					isSeconds:   strings.Contains(name, "seconds"),
				}
				if !addNewMetric(key, histogram) {
					continue
				}
			} else {
				histogram = samples.(*histogramSamples)
			}
			histogram.updatedAt = t0
			buckets := convertHistogram(msg.GetHistogram())

			updated := histogramSampleCount(buckets) != histogramSampleCount(histogram.prev)
			if updated {
				b := buckets
				if histogram.prev != nil {
					// Previous sample exists, deduct the counts from it to get the quantiles
					// of the last period.
					b = slices.Clone(buckets)
					subtractHistogram(b, histogram.prev)
				}
				histogram.p50.push(float32(getHistogramQuantile(b, 0.50)))
				histogram.p90.push(float32(getHistogramQuantile(b, 0.90)))
				histogram.p99.push(float32(getHistogramQuantile(b, 0.99)))
				histogram.bits.mark(true)
			} else {
				histogram.p50.push(0.0)
				histogram.p90.push(0.0)
				histogram.p99.push(0.0)
				histogram.bits.mark(false)
			}
			histogram.prev = buckets
		} else {
			var s *gaugeOrCounterSamples
			if samples, ok := dc.metrics[key]; !ok {
				s = &gaugeOrCounterSamples{
					baseSamples: baseSamples{name: key.fqName(), labels: concatLabels(msg.Label)},
				}
				if !addNewMetric(key, s) {
					continue
				}
			} else {
				s = samples.(*gaugeOrCounterSamples)
			}
			s.updatedAt = t0

			var value float64
			switch {
			case msg.Counter != nil:
				value = msg.Counter.GetValue()
			case msg.Gauge != nil:
				value = msg.Gauge.GetValue()
			case msg.Summary != nil:
				value = msg.Summary.GetSampleSum() / float64(msg.Summary.GetSampleCount())
			default:
				value = -1.0
			}
			s.samples.push(float32(value))
			s.bits.mark(true)
		}

		numSampled++
	}

	health.OK(fmt.Sprintf("Sampled %d metrics in %s, next collection at %s", numSamples, time.Since(t0), t0.Add(samplingInterval)))
}

var sep = []byte{model.SeparatorByte}

// newMetricKey constructs a key to uniquely identify a specific metric. Designed
// to avoid heap allocations.
func newMetricKey(desc *prometheus.Desc, labels []*dto.LabelPair) metricKey {
	var xxh xxhash.Digest
	xxh.Reset()
	for _, lp := range labels {
		xxh.WriteString(lp.GetName())
		xxh.Write(sep)
		xxh.WriteString(lp.GetValue())
	}
	return metricKey{
		desc:       desc,
		labelsHash: xxh.Sum64(),
	}
}

func concatLabels(labels []*dto.LabelPair) string {
	var b strings.Builder
	for i, lp := range labels {
		b.WriteString(lp.GetName())
		b.WriteByte('=')
		b.WriteString(lp.GetValue())
		if i < len(labels)-1 {
			b.WriteByte(' ')
		}
	}
	return b.String()
}
