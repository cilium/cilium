package metrics

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var Cell = cell.Metric(NewMetrics)

var logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "policy-metrics")

type Metrics struct {
	PolicySelections metric.DeletableVec[metric.Gauge]
	Selections       metric.DeletableVec[metric.Gauge]
}

// TODO: Spin this up and provide some example graphs via Grafana.
func NewMetrics() *Metrics {
	return &Metrics{
		Selections: metric.NewGaugeVec(metric.GaugeOpts{
			Name:      "selections_total",
			Help:      "Number of selections per policy type and selector type.",
			Namespace: "cilium",
		}, []string{"type", "selector_type"}),
		PolicySelections: metric.NewGaugeVec(metric.GaugeOpts{
			Name:      "policy_selections",
			Help:      "Number of selections per policy type",
			Namespace: "cilium",
		}, []string{"namespace", "type", "policy"}),
	}
}

func (m *Metrics) SetPolicySelections(namespace, policyType, policyName string, selections int) {
	if m.PolicySelections == nil {
		return
	}
	if selections < 0 {
		logger.Error("BUG: negative policy selections metrics value")
	}
	m.PolicySelections.WithLabelValues(namespace, policyType, policyName).Set(float64(selections))
}

func (m *Metrics) DeletePolicySelections(namespace, policyType, policyName string) {
	if m.PolicySelections == nil {
		return
	}
	m.PolicySelections.DeleteLabelValues(namespace, policyType, policyName)
}

func (m *Metrics) SetSelections(selectorType, policyType string, selections int) {
	if m.Selections == nil {
		return
	}
	if selections < 0 {
		logger.Error("BUG: negative selections metrics value")
	}
	fmt.Println("[metric] setting metric:", policyType, selectorType, "=>", float64(selections))
	m.Selections.WithLabelValues(policyType, selectorType).Set(float64(selections))
}
