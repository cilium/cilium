// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric/collections"
)

var logger = logrus.WithField(logfields.LogSubsys, "metric")

// WithMetadata is the interface implemented by any metric defined in this package. These typically embed existing
// prometheus metric types and add additional metadata. In addition, these metrics have the concept of being enabled
// or disabled which is used in place of conditional registration so all metric types can always be registered.
type WithMetadata interface {
	IsEnabled() bool
	SetEnabled(bool)
	Opts() Opts
}

// metric is a "base" structure which can be embedded to provide common functionality.
type metric struct {
	enabled bool
	opts    Opts
	labels  *labelSet
}

// forEachLabelVector performs a product of all possible label value combinations
// and calls the provided function for each combination.
func (b *metric) forEachLabelVector(fn func(lvls []string)) {
	if b.labels == nil {
		return
	}
	var labelValues [][]string
	for _, label := range b.labels.lbls {
		labelValues = append(labelValues, maps.Keys(label.Values))
	}
	for _, labelVector := range collections.CartesianProduct(labelValues...) {
		fn(labelVector)
	}
}

// checkLabelValues checks that the provided label values are within the range
// of provided label values, if labels where defined using the Labels type.
// Violations are logged as errors for detection, but metrics should still
// be collected as is.
func (b *metric) checkLabelValues(lvs ...string) {
	if b.labels == nil {
		return
	}
	if err := b.labels.checkLabelValues(lvs); err != nil {
		logger.WithError(err).Error("metric label constraints violated")
	}
}

func (b *metric) checkLabels(labels prometheus.Labels) {
	if b.labels == nil {
		return
	}
	if err := b.labels.checkLabels(labels); err != nil {
		logger.WithError(err).Error("metric label constraints violated")
	}
}

func (b *metric) IsEnabled() bool {
	return b.enabled
}

func (b *metric) SetEnabled(e bool) {
	b.enabled = e
}

func (b *metric) Opts() Opts {
	return b.opts
}

// Vec is a generic type to describe the vectorized version of another metric type, for example Vec[Counter] would be
// our version of a prometheus.CounterVec.
type Vec[T any] interface {
	prometheus.Collector
	WithMetadata

	// CurryWith returns a vector curried with the provided labels, i.e. the
	// returned vector has those labels pre-set for all labeled operations performed
	// on it. The cardinality of the curried vector is reduced accordingly. The
	// order of the remaining labels stays the same (just with the curried labels
	// taken out of the sequence – which is relevant for the
	// (GetMetric)WithLabelValues methods). It is possible to curry a curried
	// vector, but only with labels not yet used for currying before.
	//
	// The metrics contained in the `Vec[T]` are shared between the curried and
	// uncurried vectors. They are just accessed differently. Curried and uncurried
	// vectors behave identically in terms of collection. Only one must be
	// registered with a given registry (usually the uncurried version). The Reset
	// method deletes all metrics, even if called on a curried vector.
	CurryWith(labels prometheus.Labels) (Vec[T], error)

	// GetMetricWith returns the `T` for the given Labels map (the label names
	// must match those of the variable labels in Desc). If that label map is
	// accessed for the first time, a new `T` is created. Implications of
	// creating a `T` without using it and keeping the `T` for later use are
	// the same as for GetMetricWithLabelValues.
	//
	// An error is returned if the number and names of the Labels are inconsistent
	// with those of the variable labels in Desc (minus any curried labels).
	//
	// This method is used for the same purpose as
	// GetMetricWithLabelValues(...string). See there for pros and cons of the two
	// methods.
	GetMetricWith(labels prometheus.Labels) (T, error)

	// GetMetricWithLabelValues returns the `T` for the given slice of label
	// values (same order as the variable labels in Desc). If that combination of
	// label values is accessed for the first time, a new `T` is created.
	//
	// It is possible to call this method without using the returned `T` to only
	// create the new `T` but leave it at its starting value 0.
	//
	// Keeping the `T` for later use is possible (and should be considered if
	// performance is critical), but keep in mind that Reset, DeleteLabelValues and
	// Delete can be used to delete the `T` from the `Vec[T]`, assuming it also
	// implements `DeletableVec[T]`. In that case,
	// the `T` will still exist, but it will not be exported anymore, even if a
	// `T` with the same label values is created later.
	//
	// An error is returned if the number of label values is not the same as the
	// number of variable labels in Desc (minus any curried labels).
	//
	// Note that for more than one label value, this method is prone to mistakes
	// caused by an incorrect order of arguments. Consider GetMetricWith(Labels) as
	// an alternative to avoid that type of mistake. For higher label numbers, the
	// latter has a much more readable (albeit more verbose) syntax, but it comes
	// with a performance overhead (for creating and processing the Labels map).
	GetMetricWithLabelValues(lvs ...string) (T, error)

	// With works as GetMetricWith, but panics where GetMetricWithLabels would have
	// returned an error. Not returning an error allows shortcuts like
	//
	//	myVec.With(prometheus.Labels{"code": "404", "method": "GET"}).Add(42)
	With(labels prometheus.Labels) T

	// WithLabelValues works as GetMetricWithLabelValues, but panics where
	// GetMetricWithLabelValues would have returned an error. Not returning an
	// error allows shortcuts like
	//
	//	myVec.WithLabelValues("404", "GET").Add(42)
	WithLabelValues(lvs ...string) T
}

// DeletableVec is a generic type to describe a vectorized version of another metric type, like Vec[T], but with the
// additional ability to remove labels without re-creating the metric.
type DeletableVec[T any] interface {
	Vec[T]

	// Delete deletes the metric where the variable labels are the same as those
	// passed in as labels. It returns true if a metric was deleted.
	//
	// It is not an error if the number and names of the Labels are inconsistent
	// with those of the VariableLabels in Desc. However, such inconsistent Labels
	// can never match an actual metric, so the method will always return false in
	// that case.
	//
	// This method is used for the same purpose as DeleteLabelValues(...string). See
	// there for pros and cons of the two methods.
	Delete(labels prometheus.Labels) bool

	// DeleteLabelValues removes the metric where the variable labels are the same
	// as those passed in as labels (same order as the VariableLabels in Desc). It
	// returns true if a metric was deleted.
	//
	// It is not an error if the number of label values is not the same as the
	// number of VariableLabels in Desc. However, such inconsistent label count can
	// never match an actual metric, so the method will always return false in that
	// case.
	//
	// Note that for more than one label value, this method is prone to mistakes
	// caused by an incorrect order of arguments. Consider Delete(Labels) as an
	// alternative to avoid that type of mistake. For higher label numbers, the
	// latter has a much more readable (albeit more verbose) syntax, but it comes
	// with a performance overhead (for creating and processing the Labels map).
	// See also the CounterVec example.
	DeleteLabelValues(lvs ...string) bool

	// DeletePartialMatch deletes all metrics where the variable labels contain all of those
	// passed in as labels. The order of the labels does not matter.
	// It returns the number of metrics deleted.
	//
	// Note that curried labels will never be matched if deleting from the curried vector.
	// To match curried labels with DeletePartialMatch, it must be called on the base vector.
	DeletePartialMatch(labels prometheus.Labels) int

	// Reset deletes all metrics in this vector.
	Reset()
}

// Opts are a modified and extended version of the prometheus.Opts
// https://pkg.go.dev/github.com/prometheus/client_golang/prometheus#Opts
type Opts struct {
	// Namespace, Subsystem, and Name are components of the fully-qualified
	// name of the Metric (created by joining these components with
	// "_"). Only Name is mandatory, the others merely help structuring the
	// name. Note that the fully-qualified name of the metric must be a
	// valid Prometheus metric name.
	Namespace string
	Subsystem string
	Name      string

	// Help provides information about this metric.
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

	// The name used to enable/disable this metric via the config/flags
	ConfigName string

	// If true, the metric has to be explicitly enabled via config or flags
	Disabled bool
}

func (b Opts) GetConfigName() string {
	if b.ConfigName == "" {
		return prometheus.BuildFQName(b.Namespace, b.Subsystem, b.Name)
	}
	return b.ConfigName
}

// Label represents a metric label with a pre-defined range of values.
// This is used with the NewxxxVecWithLabels metrics constructors to initialize
// vector metrics with known label value ranges, avoiding empty metrics.
type Label struct {
	Name string
	// If defined, only these values are allowed.
	Values Values
}

// Values is a distinct set of possible label values for a particular Label.
type Values map[string]struct{}

// NewValues constructs a Values type from a set of strings.
func NewValues(vs ...string) Values {
	vals := Values{}
	for _, v := range vs {
		vals[v] = struct{}{}
	}
	return vals
}

// Labels is a slice of labels that represents a label set for a vector type
// metric.
type Labels []Label

func (lbls Labels) labelNames() []string {
	lns := make([]string, len(lbls))
	for i, label := range lbls {
		lns[i] = label.Name
	}
	return lns
}

type labelSet struct {
	lbls Labels
	m    map[string]map[string]struct{}
}

func (l *labelSet) namesToValues() map[string]map[string]struct{} {
	if l.m != nil {
		return l.m
	}
	l.m = make(map[string]map[string]struct{})
	for _, label := range l.lbls {
		l.m[label.Name] = label.Values
	}
	return l.m
}

func (l *labelSet) checkLabels(labels prometheus.Labels) error {
	for name, value := range labels {
		if lvs, ok := l.namesToValues()[name]; ok {
			if _, ok := lvs[value]; !ok {
				return fmt.Errorf("value %s not allowed for label %s (should be one of %v)", value, name, lvs)
			}
		} else {
			return fmt.Errorf("invalid label name: %s", name)
		}
	}
	return nil
}

func (l *labelSet) checkLabelValues(lvs []string) error {
	if len(l.lbls) != len(lvs) {
		return fmt.Errorf("invalid labels")
	}
	for i, label := range l.lbls {
		if _, ok := label.Values[lvs[i]]; !ok {
			return fmt.Errorf("invalid label value")
		}
	}
	return nil
}

// initLabels is a helper function to initialize the labels of a metric.
// It is used by xxxVecWithLabels metrics constructors to initialize the
// labels of the metric and the vector (i.e. registering all possible label value combinations).
func initLabels[T any](m *metric, labels Labels, vec Vec[T], disabled bool) {
	if disabled {
		return
	}
	m.labels = &labelSet{lbls: labels}
	m.forEachLabelVector(func(vs []string) {
		vec.WithLabelValues(vs...)
	})
}
