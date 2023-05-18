// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MetricsSuite struct{}

var _ = Suite(&MetricsSuite{})

func (s *MetricsSuite) TestAPIEventsTSHelperMiddleware(c *C) {
	for _, test := range []struct {
		url         string
		statusCode  int
		expectEvent bool
	}{
		{url: "https://10.0.0.0/v1/endpoint/id:00000000", statusCode: http.StatusOK, expectEvent: true},
		{url: "https://10.0.0.0/v1/endpoint/id:00000000", statusCode: http.StatusNotFound, expectEvent: true},
		{url: "", statusCode: http.StatusNotFound, expectEvent: false}, // invalid urls should not be emitted.
	} {
		req, err := http.NewRequest(http.MethodGet, test.url, nil)
		c.Assert(err, Equals, nil)
		gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{}, []string{LabelEventSource, LabelScope, LabelAction})
		hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_api_hist"}, []string{LabelEventSource, LabelScope, LabelAction})
		middleware := &APIEventTSHelper{
			Next:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.statusCode) }),
			TSGauge:   gauge,
			Histogram: hist,
		}
		middleware.ServeHTTP(httptest.NewRecorder(), req)
		v := testutil.ToFloat64(gauge.WithLabelValues(LabelEventSourceAPI, "/v1/endpoint", http.MethodGet))
		c.Assert(v >= float64(time.Now().Unix()), Equals, test.expectEvent)
		c.Assert(testutil.CollectAndCount(hist, "test_api_hist") == 1, Equals, test.expectEvent)
	}
}

func (s *MetricsSuite) Test_getShortPath(c *C) {
	tests := []struct {
		args string
		want string
	}{
		{
			args: "/v1/config",
			want: "/v1/config",
		},
		{
			args: "/v1/endpoint/cilium-local:0",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/endpoint/container-id:597b3583727d51206d0a08df82b484925b458ff1fc04d1a98637435b73b9b47d",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/endpoint/container-id:6813916d21c3311e62078a232942504937f1b4a8b2e32e40044f188da986fe41",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/endpoint/container-id:cf2c692f24933fc12d51dc0b42d92708a3c73e8f3a0f517c3ed2e7628ba57d92",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/healthz",
			want: "/v1/healthz",
		},
		{
			args: "/v1/ipam",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/10.16.11.109",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/10.16.169.230",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/10.16.69.17",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:2f5f",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:9dec",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:d5c7",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:d5c7/hello",
			want: "/v1/ipam",
		},
		{
			args: "/v1",
			want: "/v1",
		},
		{
			args: "/////",
			want: "//",
		},
		{
			args: "//",
			want: "//",
		},
		{
			args: "/",
			want: "/",
		},
		{
			args: "hello/foo/bar/",
			want: "hello/foo/bar",
		},
		{
			args: "hello/foo//",
			want: "hello/foo/",
		},
		{
			args: "hello/foo/",
			want: "hello/foo/",
		},
		{
			args: "hello/foo",
			want: "hello/foo",
		},
		{
			args: "hello/",
			want: "hello/",
		},
		{
			args: "hello",
			want: "hello",
		},
		{
			args: "",
			want: "",
		},
	}
	for _, tt := range tests {
		got := getShortPath(tt.args)
		c.Assert(got, Equals, tt.want)
	}
}
