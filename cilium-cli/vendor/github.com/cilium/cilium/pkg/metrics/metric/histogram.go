// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func NewHistogram(opts HistogramOpts) Histogram {
	return &histogram{
		Histogram: prometheus.NewHistogram(opts.toPrometheus()),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    opts.opts(),
		},
	}
}

type Histogram interface {
	prometheus.Histogram
	WithMetadata
}

type histogram struct {
	prometheus.Histogram
	metric
}

func (h *histogram) Collect(metricChan chan<- prometheus.Metric) {
	if h.enabled {
		h.Histogram.Collect(metricChan)
	}
}

// Observe adds a single observation to the histogram. Observations are
// usually positive or zero. Negative observations are accepted but
// prevent current versions of Prometheus from properly detecting
// counter resets in the sum of observations. (The experimental Native
// Histograms handle negative observations properly.) See
// https://prometheus.io/docs/practices/histograms/#count-and-sum-of-observations
// for details.
func (h *histogram) Observe(val float64) {
	if h.enabled {
		h.Histogram.Observe(val)
	}
}

type Observer interface {
	prometheus.Observer
	WithMetadata
}

type observer struct {
	prometheus.Observer
	metric
}

// Observe adds a single observation to the histogram. Observations are
// usually positive or zero. Negative observations are accepted but
// prevent current versions of Prometheus from properly detecting
// counter resets in the sum of observations. (The experimental Native
// Histograms handle negative observations properly.) See
// https://prometheus.io/docs/practices/histograms/#count-and-sum-of-observations
// for details.
func (o *observer) Observe(val float64) {
	if o.enabled {
		o.Observer.Observe(val)
	}
}

func NewHistogramVec(opts HistogramOpts, labelNames []string) Vec[Observer] {
	return &histogramVec{
		ObserverVec: prometheus.NewHistogramVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    opts.opts(),
		},
	}
}

type histogramVec struct {
	prometheus.ObserverVec
	metric
}

func (cv *histogramVec) CurryWith(labels prometheus.Labels) (Vec[Observer], error) {
	vec, err := cv.ObserverVec.CurryWith(labels)
	if err == nil {
		return &histogramVec{ObserverVec: vec, metric: cv.metric}, nil
	}
	return nil, err
}

func (cv *histogramVec) GetMetricWith(labels prometheus.Labels) (Observer, error) {
	if !cv.enabled {
		return &observer{
			metric: metric{enabled: false},
		}, nil
	}

	promObserver, err := cv.ObserverVec.GetMetricWith(labels)
	if err == nil {
		return &observer{
			Observer: promObserver,
			metric:   cv.metric,
		}, nil
	}
	return nil, err
}

func (cv *histogramVec) GetMetricWithLabelValues(lvs ...string) (Observer, error) {
	if !cv.enabled {
		return &observer{
			metric: metric{enabled: false},
		}, nil
	}

	promObserver, err := cv.ObserverVec.GetMetricWithLabelValues(lvs...)
	if err == nil {
		return &observer{
			Observer: promObserver,
			metric:   cv.metric,
		}, nil
	}
	return nil, err
}

func (cv *histogramVec) With(labels prometheus.Labels) Observer {
	if !cv.enabled {
		return &observer{
			metric: metric{enabled: false},
		}
	}

	promObserver := cv.ObserverVec.With(labels)
	return &observer{
		Observer: promObserver,
		metric:   cv.metric,
	}
}

func (cv *histogramVec) WithLabelValues(lvs ...string) Observer {
	if !cv.enabled {
		return &observer{
			metric: metric{enabled: false},
		}
	}

	promObserver := cv.ObserverVec.WithLabelValues(lvs...)
	return &observer{
		Observer: promObserver,
		metric:   cv.metric,
	}
}

func (cv *histogramVec) SetEnabled(e bool) {
	if !e {
		if histVec, ok := cv.ObserverVec.(*prometheus.HistogramVec); ok {
			histVec.Reset()
		}
	}

	cv.metric.SetEnabled(e)
}

// HistogramOpts are a modified and expanded version of the prometheus.HistogramOpts.
// https://pkg.go.dev/github.com/prometheus/client_golang/prometheus#HistogramOpts
type HistogramOpts struct {
	// Namespace, Subsystem, and Name are components of the fully-qualified
	// name of the Histogram (created by joining these components with
	// "_"). Only Name is mandatory, the others merely help structuring the
	// name. Note that the fully-qualified name of the Histogram must be a
	// valid Prometheus metric name.
	Namespace string
	Subsystem string
	Name      string

	// Help provides information about this Histogram.
	//
	// Metrics with the same fully-qualified name must have the same Help
	// string.
	Help string

	// ConstLabels are used to attach fixed labels to this metric. Metrics
	// with the same fully-qualified name must have the same label names in
	// their ConstLabels.
	//
	// ConstLabels are only used rarely. In particular, do not use them to
	// attach the same labels to all your metrics. Those use cases are
	// better covered by target labels set by the scraping Prometheus
	// server, or by one specific metric (e.g. a build_info or a
	// machine_role metric). See also
	// https://prometheus.io/docs/instrumenting/writing_exporters/#target-labels-not-static-scraped-labels
	ConstLabels prometheus.Labels

	// Buckets defines the buckets into which observations are counted. Each
	// element in the slice is the upper inclusive bound of a bucket. The
	// values must be sorted in strictly increasing order. There is no need
	// to add a highest bucket with +Inf bound, it will be added
	// implicitly. If Buckets is left as nil or set to a slice of length
	// zero, it is replaced by default buckets. The default buckets are
	// DefBuckets if no buckets for a native histogram (see below) are used,
	// otherwise the default is no buckets. (In other words, if you want to
	// use both reguler buckets and buckets for a native histogram, you have
	// to define the regular buckets here explicitly.)
	Buckets []float64

	// If NativeHistogramBucketFactor is greater than one, so-called sparse
	// buckets are used (in addition to the regular buckets, if defined
	// above). A Histogram with sparse buckets will be ingested as a Native
	// Histogram by a Prometheus server with that feature enabled (requires
	// Prometheus v2.40+). Sparse buckets are exponential buckets covering
	// the whole float64 range (with the exception of the “zero” bucket, see
	// SparseBucketsZeroThreshold below). From any one bucket to the next,
	// the width of the bucket grows by a constant
	// factor. NativeHistogramBucketFactor provides an upper bound for this
	// factor (exception see below). The smaller
	// NativeHistogramBucketFactor, the more buckets will be used and thus
	// the more costly the histogram will become. A generally good trade-off
	// between cost and accuracy is a value of 1.1 (each bucket is at most
	// 10% wider than the previous one), which will result in each power of
	// two divided into 8 buckets (e.g. there will be 8 buckets between 1
	// and 2, same as between 2 and 4, and 4 and 8, etc.).
	//
	// Details about the actually used factor: The factor is calculated as
	// 2^(2^n), where n is an integer number between (and including) -8 and
	// 4. n is chosen so that the resulting factor is the largest that is
	// still smaller or equal to NativeHistogramBucketFactor. Note that the
	// smallest possible factor is therefore approx. 1.00271 (i.e. 2^(2^-8)
	// ). If NativeHistogramBucketFactor is greater than 1 but smaller than
	// 2^(2^-8), then the actually used factor is still 2^(2^-8) even though
	// it is larger than the provided NativeHistogramBucketFactor.
	//
	// NOTE: Native Histograms are still an experimental feature. Their
	// behavior might still change without a major version
	// bump. Subsequently, all NativeHistogram... options here might still
	// change their behavior or name (or might completely disappear) without
	// a major version bump.
	NativeHistogramBucketFactor float64
	// All observations with an absolute value of less or equal
	// NativeHistogramZeroThreshold are accumulated into a “zero”
	// bucket. For best results, this should be close to a bucket
	// boundary. This is usually the case if picking a power of two. If
	// NativeHistogramZeroThreshold is left at zero,
	// DefSparseBucketsZeroThreshold is used as the threshold. To configure
	// a zero bucket with an actual threshold of zero (i.e. only
	// observations of precisely zero will go into the zero bucket), set
	// NativeHistogramZeroThreshold to the NativeHistogramZeroThresholdZero
	// constant (or any negative float value).
	NativeHistogramZeroThreshold float64

	// The remaining fields define a strategy to limit the number of
	// populated sparse buckets. If NativeHistogramMaxBucketNumber is left
	// at zero, the number of buckets is not limited. (Note that this might
	// lead to unbounded memory consumption if the values observed by the
	// Histogram are sufficiently wide-spread. In particular, this could be
	// used as a DoS attack vector. Where the observed values depend on
	// external inputs, it is highly recommended to set a
	// NativeHistogramMaxBucketNumber.)  Once the set
	// NativeHistogramMaxBucketNumber is exceeded, the following strategy is
	// enacted: First, if the last reset (or the creation) of the histogram
	// is at least NativeHistogramMinResetDuration ago, then the whole
	// histogram is reset to its initial state (including regular
	// buckets). If less time has passed, or if
	// NativeHistogramMinResetDuration is zero, no reset is
	// performed. Instead, the zero threshold is increased sufficiently to
	// reduce the number of buckets to or below
	// NativeHistogramMaxBucketNumber, but not to more than
	// NativeHistogramMaxZeroThreshold. Thus, if
	// NativeHistogramMaxZeroThreshold is already at or below the current
	// zero threshold, nothing happens at this step. After that, if the
	// number of buckets still exceeds NativeHistogramMaxBucketNumber, the
	// resolution of the histogram is reduced by doubling the width of the
	// sparse buckets (up to a growth factor between one bucket to the next
	// of 2^(2^4) = 65536, see above).
	NativeHistogramMaxBucketNumber  uint32
	NativeHistogramMinResetDuration time.Duration
	NativeHistogramMaxZeroThreshold float64

	ConfigName string

	// If true, the metric has to be explicitly enabled via config or flags
	Disabled bool
}

func (ho HistogramOpts) opts() Opts {
	return Opts{
		Namespace:   ho.Namespace,
		Subsystem:   ho.Subsystem,
		Name:        ho.Name,
		Help:        ho.Help,
		ConstLabels: ho.ConstLabels,
		ConfigName:  ho.ConfigName,
		Disabled:    ho.Disabled,
	}
}

func (ho HistogramOpts) toPrometheus() prometheus.HistogramOpts {
	return prometheus.HistogramOpts{
		Namespace:                       ho.Namespace,
		Subsystem:                       ho.Subsystem,
		Name:                            ho.Name,
		Help:                            ho.Help,
		ConstLabels:                     ho.ConstLabels,
		Buckets:                         ho.Buckets,
		NativeHistogramBucketFactor:     ho.NativeHistogramBucketFactor,
		NativeHistogramZeroThreshold:    ho.NativeHistogramZeroThreshold,
		NativeHistogramMaxBucketNumber:  ho.NativeHistogramMaxBucketNumber,
		NativeHistogramMinResetDuration: ho.NativeHistogramMinResetDuration,
		NativeHistogramMaxZeroThreshold: ho.NativeHistogramMaxZeroThreshold,
	}
}
