// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// WithMetadata is the interface implemented by any metric defined in this package. These typically embed existing
// prometheus metric types and add additional metadata to the definitions which can be used to generate proper metric
// documentation from de definitions. In addition, these metrics have the concept of being enabled or disabled which
// is used in place of conditional registration so all metric types can always be registered for the purposes of
// documenting them.
type WithMetadata interface {
	IsEnabled() bool
	SetEnabled(bool)
	Opts() Opts
	Labels() LabelDescriptions
}

// metric is a "base" structure which can be embedded to provide common functionality.
type metric struct {
	opts    Opts
	enabled bool
}

func (b *metric) IsEnabled() bool {
	return b.enabled
}

func (b *metric) SetEnabled(e bool) {
	b.enabled = e
}

func (b *metric) Opts() Opts {
	return Opts(b.opts)
}

func (b *metric) Labels() LabelDescriptions {
	var labels LabelDescriptions
	for constLabel, value := range b.opts.ConstLabels {
		labels = append(labels, LabelDescription{
			Name:        constLabel.Name,
			Description: constLabel.Description,
			KnownValues: []KnownValue{
				{
					Name: value,
				},
			},
		})
	}
	return labels
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
	Subsystem Subsystem
	Name      string

	// Help provides information about this metric.
	//
	// Metrics with the same fully-qualified name must have the same Help
	// string.
	//
	// This string is included with the data in the prometheus endpoint and should be brief.
	Help string

	// Description is a more verbose description of the metric for documentation purposes.
	Description string

	// If true, the metrics are enabled unless specifically requested to be disabled
	EnabledByDefault bool

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
	ConstLabels ConstLabels
}

func (o Opts) FullyQualifiedName() string {
	var parts []string
	if o.Namespace != "" {
		parts = append(parts, o.Namespace)
	}
	if o.Subsystem.Name != "" {
		parts = append(parts, o.Subsystem.Name)
	}
	parts = append(parts, o.Name)

	return strings.Join(parts, "_")
}

type LabelDescriptions []LabelDescription

// LabelDescription, unlike traditional prometheus metric declarations contains not only the name of a label but also
// a description explaining what the label is and a list of known-values, used if the possible values of the label
// are known in advance.
type LabelDescription struct {
	Name        string
	Description string
	KnownValues []KnownValue
}

// KnownValue describes a known value for a label, like an enum.
type KnownValue struct {
	Name        string
	Description string
}

func (l LabelDescriptions) labelNames() []string {
	names := make([]string, len(l))
	for i, desc := range l {
		names[i] = desc.Name
	}
	return names
}

type ConstLabels map[ConstLabel]string

// ConstLabel is a label which is always set on a metric. ConstLabel doesn't have a known-value list unlike
// LabelDescription because the value of its label is part of the metric definition.
type ConstLabel struct {
	Name        string
	Description string
}

// Subsystem is used to describe the 'subsystem' part of a metrics full name.
type Subsystem struct {
	// Name is the string used in the metric name {namespace}_{subsystem}_{metric_name}. The underscores do not need to
	// be added. If left empty, the full metric name will not contain the subsystem ({namespace}_{metric_name}).
	Name string
	// DocName is the name of the subsystem as displayed in the generated documentation to allow for spaces, capitals,
	// and punctuation otherwise not allowed in the metric names. If left blank the `Name` will be used instead.
	DocName     string
	Description string
}

func (l ConstLabels) toPrometheus() prometheus.Labels {
	labels := make(prometheus.Labels, len(l))
	for label, value := range l {
		labels[label.Name] = value
	}
	return labels
}

// Vec is a generic type to describe the vectorized version of another metric type, for example Vec[Counter] would be
// our version of a prometheus.CounterVec.
type Vec[T any] interface {
	WithMetadata

	CurryWith(labels prometheus.Labels) (Vec[T], error)
	GetMetricWith(labels prometheus.Labels) (T, error)
	GetMetricWithLabelValues(lvs ...string) (T, error)
	With(labels prometheus.Labels) T
	WithLabelValues(lvs ...string) T
	LabelDescriptions() LabelDescriptions
}

// DeletableVec is a generic type to describe a vectorized version of another metric type, like Vec[T], but with the
// additional ability to remove labels without re-creating the metric.
type DeletableVec[T any] interface {
	Vec[T]
	Delete(labels prometheus.Labels) bool
	DeleteLabelValues(lvs ...string) bool
	DeletePartialMatch(labels prometheus.Labels) int
	Reset()
}
