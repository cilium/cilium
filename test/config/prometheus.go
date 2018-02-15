package config

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/sirupsen/logrus"
)

var (
	// GatewayURL is the endpoint where the Prometheus metric gateway is
	// listening.
	GatewayURL = "http://localhost:9091/"
	// PrometheusEnabled boolean specifies whether to activate
	PrometheusEnabled = false
	// PrometheusJob job name to set in Prometheus metric.
	PrometheusJob = "ginkgoTest"
	// PrometheusGroups group name to set in the Prometheus metric.
	PrometheusGroups = push.HostnameGroupingKey()
)

// PrometheusMetrics maps the location of a Prometheus metric to the metric's value
type PrometheusMetrics map[string]string

// SetGatewayURL it sets the GatewayURL using basic HTTP authentication
func SetGatewayURL(URL string, user string, password string) error {
	u, err := url.Parse(URL)
	if err != nil {
		return err
	}
	u.User = url.UserPassword(user, password)
	GatewayURL = u.String()
	return nil
}

// PushInfo pushes the given metrics to Prometheus gateway
func PushInfo(metrics *PrometheusMetrics) error {

	if !PrometheusEnabled {
		logrus.Debug("Prometheus Exporter is not enabled")
		return nil
	}

	data := []prometheus.Collector{}
	for k, v := range *metrics {
		gauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: k,
			Help: k,
		})
		number, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("cannot convert '%v' to float: %s", v, err)
		}
		gauge.Set(number)
		data = append(data, gauge)
	}
	err := push.Collectors(PrometheusJob, PrometheusGroups, GatewayURL, data...)
	return err
}
