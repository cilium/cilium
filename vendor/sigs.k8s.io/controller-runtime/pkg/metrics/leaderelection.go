package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/tools/leaderelection"
)

// This file is copied and adapted from k8s.io/component-base/metrics/prometheus/clientgo/leaderelection
// which registers metrics to the k8s legacy Registry. We require very
// similar functionality, but must register metrics to a different Registry.

var (
	leaderGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "leader_election_master_status",
		Help: "Gauge of if the reporting system is master of the relevant lease, 0 indicates backup, 1 indicates master. 'name' is the string used to identify the lease. Please make sure to group by name.",
	}, []string{"name"})

	leaderSlowpathCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "leader_election_slowpath_total",
		Help: "Total number of slow path exercised in renewing leader leases. 'name' is the string used to identify the lease. Please make sure to group by name.",
	}, []string{"name"})
)

func init() {
	Registry.MustRegister(leaderGauge)
	leaderelection.SetProvider(leaderelectionMetricsProvider{})
}

type leaderelectionMetricsProvider struct{}

func (leaderelectionMetricsProvider) NewLeaderMetric() leaderelection.LeaderMetric {
	return leaderElectionPrometheusAdapter{}
}

type leaderElectionPrometheusAdapter struct{}

func (s leaderElectionPrometheusAdapter) On(name string) {
	leaderGauge.WithLabelValues(name).Set(1.0)
}

func (s leaderElectionPrometheusAdapter) Off(name string) {
	leaderGauge.WithLabelValues(name).Set(0.0)
}

func (leaderElectionPrometheusAdapter) SlowpathExercised(name string) {
	leaderSlowpathCounter.WithLabelValues(name).Inc()
}
