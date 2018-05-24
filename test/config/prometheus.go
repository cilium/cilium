// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
func PushInfo(metrics PrometheusMetrics) error {

	if !PrometheusEnabled {
		logrus.Debug("Prometheus Exporter is not enabled")
		return nil
	}

	data := []prometheus.Collector{}
	for k, v := range metrics {
		gauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: k,
			Help: k,
		})
		number, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("cannot convert '%s' to float: %s", v, err)
		}
		gauge.Set(number)
		data = append(data, gauge)
	}
	return push.Collectors(PrometheusJob, PrometheusGroups, GatewayURL, data...)
}
