package layer2

import "github.com/prometheus/client_golang/prometheus"

var stats = metrics{
	in: prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "metallb",
		Subsystem: "layer2",
		Name:      "requests_received",
		Help:      "Number of layer2 requests received for owned IPs",
	}, []string{
		"ip",
	}),

	out: prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "metallb",
		Subsystem: "layer2",
		Name:      "responses_sent",
		Help:      "Number of layer2 responses sent for owned IPs in response to requests",
	}, []string{
		"ip",
	}),

	gratuitous: prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "metallb",
		Subsystem: "layer2",
		Name:      "gratuitous_sent",
		Help:      "Number of gratuitous layer2 packets sent for owned IPs as a result of failovers",
	}, []string{
		"ip",
	}),
}

type metrics struct {
	in         *prometheus.CounterVec
	out        *prometheus.CounterVec
	gratuitous *prometheus.CounterVec
}

func init() {
	prometheus.MustRegister(stats.in)
	prometheus.MustRegister(stats.out)
	prometheus.MustRegister(stats.gratuitous)
}

func (m *metrics) GotRequest(addr string) {
	m.in.WithLabelValues(addr).Add(1)
}

func (m *metrics) SentResponse(addr string) {
	m.out.WithLabelValues(addr).Add(1)
}

func (m *metrics) SentGratuitous(addr string) {
	m.gratuitous.WithLabelValues(addr).Add(1)
}
