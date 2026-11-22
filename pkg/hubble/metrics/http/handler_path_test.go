// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package http

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

const (
	requestsTotal   = "hubble_http_requests_total"
	responsesTotal  = "hubble_http_responses_total"
	durationSeconds = "hubble_http_request_duration_seconds"
)

func newPathHandler(t *testing.T, v2 bool, cfg *api.MetricConfig) (*httpHandler, *prometheus.Registry) {
	t.Helper()
	h := &httpHandler{useV2: v2}
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, h.Init(reg, cfg))
	return h, reg
}

func pathConfig(onMiss api.OnMissPolicy, templates ...string) *api.MetricConfig {
	return &api.MetricConfig{PathContext: &api.PathContext{Templates: templates, OnMiss: onMiss}}
}

func httpFlow(typ pb.L7FlowType, url string) *pb.Flow {
	return &pb.Flow{
		TrafficDirection: pb.TrafficDirection_INGRESS,
		Source:           &pb.Endpoint{Namespace: "ns", PodName: "client"},
		Destination:      &pb.Endpoint{Namespace: "ns", PodName: "server"},
		L7: &pb.Layer7{
			Type:      typ,
			LatencyNs: 1000,
			Record: &pb.Layer7_Http{Http: &pb.HTTP{
				Code:     200,
				Method:   "GET",
				Protocol: "HTTP/1.1",
				Url:      url,
			}},
		},
	}
}

// samplesByPath returns observation counts per metric family and path value.
func samplesByPath(t *testing.T, reg *prometheus.Registry) map[string]map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)

	out := make(map[string]map[string]float64)
	for _, f := range families {
		byPath := make(map[string]float64)
		for _, m := range f.GetMetric() {
			path := "<no path label>"
			for _, l := range m.GetLabel() {
				if l.GetName() == "path" {
					path = l.GetValue()
				}
			}
			byPath[path] += sampleCount(m)
		}
		out[f.GetName()] = byPath
	}
	return out
}

func sampleCount(m *dto.Metric) float64 {
	if c := m.GetCounter(); c != nil {
		return c.GetValue()
	}
	return float64(m.GetHistogram().GetSampleCount())
}

func labelNames(t *testing.T, reg *prometheus.Registry, family string) []string {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		require.NotEmpty(t, f.GetMetric())
		var names []string
		for _, l := range f.GetMetric()[0].GetLabel() {
			names = append(names, l.GetName())
		}
		return names
	}
	t.Fatalf("metric family %s not gathered", family)
	return nil
}

func TestPathLabelSetPerMetric(t *testing.T) {
	cfg := func() *api.MetricConfig {
		c := pathConfig(api.OnMissPolicy{}, "/users/{id}")
		c.ContextOptionConfigs = []*api.ContextOptionConfig{{Name: "sourceContext", Values: []string{"pod"}}}
		return c
	}

	t.Run("http emits path on three metrics", func(t *testing.T) {
		h, reg := newPathHandler(t, false, cfg())
		require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_REQUEST, "http://h/users/1")))
		require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/users/1")))

		assert.Equal(t, map[string]map[string]float64{
			requestsTotal:   {"/users/{id}": 1},
			responsesTotal:  {"/users/{id}": 1},
			durationSeconds: {"/users/{id}": 1},
		}, samplesByPath(t, reg))
		assert.ElementsMatch(t, []string{"source", "method", "protocol", "reporter", "path"}, labelNames(t, reg, requestsTotal))
		assert.ElementsMatch(t, []string{"source", "method", "protocol", "status", "reporter", "path"}, labelNames(t, reg, responsesTotal))
		assert.ElementsMatch(t, []string{"source", "method", "reporter", "path"}, labelNames(t, reg, durationSeconds))
	})

	t.Run("httpV2 emits path on two metrics", func(t *testing.T) {
		h, reg := newPathHandler(t, true, cfg())
		require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/users/1")))

		assert.Equal(t, map[string]map[string]float64{
			requestsTotal:   {"/users/{id}": 1},
			durationSeconds: {"/users/{id}": 1},
		}, samplesByPath(t, reg))
		assert.ElementsMatch(t, []string{"source", "method", "protocol", "status", "reporter", "path"}, labelNames(t, reg, requestsTotal))
	})

	t.Run("unset pathContext adds no label", func(t *testing.T) {
		for _, v2 := range []bool{false, true} {
			h, reg := newPathHandler(t, v2, &api.MetricConfig{})
			require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/users/1")))
			for family, byPath := range samplesByPath(t, reg) {
				assert.Equal(t, map[string]float64{"<no path label>": 1}, byPath, family)
			}
		}
	})
}

func TestPathLabelMatching(t *testing.T) {
	// The first template would win if matching ran on the decoded path.
	templates := []string{
		"/api/v1/users/{id}/orders",
		"/api/v1/{user}/orders",
		"/reports/my%20report",
		"/reports/{name}",
		"/some/path",
		"/static/{rest...}",
	}

	tests := []struct {
		name string
		url  string
		want string
	}{
		{"plain match", "http://h/api/v1/users/42/orders", "/api/v1/users/{id}/orders"},
		{"query string is ignored", "http://h/api/v1/users/42/orders?token=abc&x=1", "/api/v1/users/{id}/orders"},
		{"fragment is ignored", "http://h/some/path#frag", "/some/path"},
		{"percent-encoding matches byte for byte", "http://h/reports/my%20report", "/reports/my%20report"},
		{"encoded slash does not split a segment", "http://h/api/v1/users%2Fadmin/orders", "/api/v1/{user}/orders"},
		{"userinfo is ignored", "http://user:HUBBLE_REDACTED@myhost/some/path", "/some/path"},
		{"greedy tail", "http://h/static/css/app.css", "/static/{rest...}"},
		{"trailing slash is literal", "http://h/some/path/", "other"},
		{"no template matches", "http://h/healthz", "other"},
		// ParseURL turns an empty :path into "/".
		{"root path", "http://h/", "other"},
		{"empty URL", "", "other"},
		{"host with a space", "http://my%20host/some/path", "other"},
		{"unterminated IPv6 host", "http://[::1/some/path", "other"},
		{"non-numeric port", "http://h:abc/some/path", "other"},
		// ParseURL's fallback re-escapes "/a%zz" to "/a%25zz".
		{"invalid escape from the ParseURL fallback", "http://h/reports/a%25zz", "/reports/{name}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, reg := newPathHandler(t, true, pathConfig(api.OnMissPolicy{Value: "other"}, templates...))
			require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, tt.url)))
			assert.Equal(t, map[string]float64{tt.want: 1}, samplesByPath(t, reg)[requestsTotal])
		})
	}
}

func TestPathLabelOnMiss(t *testing.T) {
	t.Run("omitted onMiss emits an empty value", func(t *testing.T) {
		h, reg := newPathHandler(t, true, pathConfig(api.OnMissPolicy{}, "/a"))
		require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/b")))
		assert.Equal(t, map[string]float64{"": 1}, samplesByPath(t, reg)[requestsTotal])
	})

	t.Run("emit counts an unparseable URL under the miss value on every metric", func(t *testing.T) {
		h, reg := newPathHandler(t, false, pathConfig(api.OnMissPolicy{Action: api.OnMissEmit, Value: "other"}, "/a"))
		require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_REQUEST, "http://my%20host/a")))
		require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://my%20host/a")))
		assert.Equal(t, map[string]map[string]float64{
			requestsTotal:   {"other": 1},
			responsesTotal:  {"other": 1},
			durationSeconds: {"other": 1},
		}, samplesByPath(t, reg))
	})

	for _, v2 := range []bool{false, true} {
		t.Run("drop_sample records nothing for a miss", func(t *testing.T) {
			h, reg := newPathHandler(t, v2, pathConfig(api.OnMissPolicy{Action: api.OnMissDropSample, Value: "ignored"}, "/a"))
			require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_REQUEST, "http://h/b")))
			require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/b")))
			require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://[::1/a")))
			assert.Empty(t, samplesByPath(t, reg))

			// A hit is still recorded.
			require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/a")))
			for family, byPath := range samplesByPath(t, reg) {
				assert.Equal(t, map[string]float64{"/a": 1}, byPath, family)
			}
		})
	}
}

// V1 matches the request and response flows separately.
func TestPathLabelRequestResponseAgree(t *testing.T) {
	h, reg := newPathHandler(t, false, pathConfig(api.OnMissPolicy{}, "/users/{id}"))
	require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_REQUEST, "http://h/users/7?verbose=1")))
	require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/users/7?verbose=1")))
	got := samplesByPath(t, reg)
	assert.Equal(t, got[requestsTotal], got[responsesTotal])
	assert.Equal(t, map[string]float64{"/users/{id}": 1}, got[requestsTotal])
}

func TestPathLabelInitRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *api.MetricConfig
		wantErr string
	}{
		{"bad template", pathConfig(api.OnMissPolicy{}, "/b_{bucket}"), "pathContext.templates"},
		{"unknown onMiss.action", pathConfig(api.OnMissPolicy{Action: "skip"}, "/a"), "pathContext.onMiss.action"},
		{"onMiss.value is a template", pathConfig(api.OnMissPolicy{Value: "/a"}, "/a"), "is also a template"},
		{
			"path in contextOptions",
			&api.MetricConfig{ContextOptionConfigs: []*api.ContextOptionConfig{{Name: "path", Values: []string{"/a"}}}},
			"not a context option",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, v2 := range []bool{false, true} {
				h := &httpHandler{useV2: v2}
				require.ErrorContains(t, h.Init(prometheus.NewRegistry(), tt.cfg), tt.wantErr)
			}
		})
	}
}

// The leading comma with no context options is existing Status behaviour.
func TestPathLabelStatus(t *testing.T) {
	h, _ := newPathHandler(t, true, pathConfig(api.OnMissPolicy{Action: api.OnMissDropSample}, "/a", "/b"))
	assert.Equal(t, ",exemplars=false,pathTemplates=2,onMiss=drop_sample", h.Status())

	h, _ = newPathHandler(t, true, pathConfig(api.OnMissPolicy{}, "/a"))
	assert.Equal(t, ",exemplars=false,pathTemplates=1,onMiss=emit", h.Status())
}

// Pod cleanup matches on the pod label alone, so "path" must not get in the way.
func TestPathLabelPodDeletion(t *testing.T) {
	cfg := pathConfig(api.OnMissPolicy{}, "/users/{id}")
	cfg.ContextOptionConfigs = []*api.ContextOptionConfig{{Name: "sourceContext", Values: []string{"pod"}}}
	h, reg := newPathHandler(t, false, cfg)

	require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_REQUEST, "http://h/users/1")))
	require.NoError(t, h.ProcessFlow(t.Context(), httpFlow(pb.L7FlowType_RESPONSE, "http://h/other")))
	require.Len(t, samplesByPath(t, reg), 3)

	for _, vec := range h.ListMetricVec() {
		h.Context().DeleteMetricsAssociatedWithPod("client", "ns", vec)
	}
	assert.Empty(t, samplesByPath(t, reg))
}
