// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// PodToPod generates one HTTP request from each client pod
// to each echo (server) pod in the test context. The remote Pod is contacted
// directly, no DNS is involved.
func PodToPod(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToPod{
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
	}
}

// podToPod implements a Scenario.
type podToPod struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
}

func (s *podToPod) Name() string {
	return "pod-to-pod"
}

func (s *podToPod) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference
		if !hasAllLabels(client, s.sourceLabels) {
			continue
		}
		for _, echo := range ct.EchoPods() {
			if !hasAllLabels(echo, s.destinationLabels) {
				continue
			}
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
					if s.method == "" {
						a.ExecInPod(ctx, ct.CurlCommand(echo, ipFam))
					} else {
						a.ExecInPod(ctx, ct.CurlCommand(echo, ipFam, "-X", s.method))
					}

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
					a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))

					a.ValidateMetrics(ctx, echo, a.GetIngressMetricsRequirements())
					a.ValidateMetrics(ctx, echo, a.GetEgressMetricsRequirements())
				})
			})

			i++
		}
	}
}

func PodToPodWithEndpoints(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToPodWithEndpoints{
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
		method:            options.method,
		path:              options.path,
	}
}

// podToPodWithEndpoints implements a Scenario.
type podToPodWithEndpoints struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
	method            string
	path              string
}

func (s *podToPodWithEndpoints) Name() string {
	return "pod-to-pod-with-endpoints"
}

func (s *podToPodWithEndpoints) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference
		if !hasAllLabels(client, s.sourceLabels) {
			continue
		}
		for _, echo := range ct.EchoPods() {
			if !hasAllLabels(echo, s.destinationLabels) {
				continue
			}

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				s.curlEndpoints(ctx, t, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, echo, ipFam)
			})

			i++
		}
	}
}

func (s *podToPodWithEndpoints) curlEndpoints(ctx context.Context, t *check.Test, name string,
	client *check.Pod, echo check.TestPeer, ipFam features.IPFamily) {
	ct := t.Context()
	baseURL := fmt.Sprintf("%s://%s:%d", echo.Scheme(), echo.Address(ipFam), echo.Port())
	var curlOpts []string
	if s.method != "" {
		curlOpts = append(curlOpts, "-X", s.method)
	}

	// Manually construct an HTTP endpoint for each API endpoint.
	paths := []string{"public", "private"}
	if s.path != "" { // Override default paths if one is set
		paths = []string{s.path}
	}

	for _, path := range paths {
		epName := fmt.Sprintf("%s-%s", name, path)
		url := fmt.Sprintf("%s/%s", baseURL, path)
		ep := check.HTTPEndpointWithLabels(epName, url, echo.Labels())

		t.NewAction(s, epName, client, ep, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(ep, ipFam, curlOpts...))

			a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
			a.ValidateFlows(ctx, ep, a.GetIngressRequirements(check.FlowParameters{}))
		})

		// Additionally test private endpoint access with HTTP header expected by policy.
		if path == "private" {
			epName += "with-header"
			labels := echo.Labels()
			labels["X-Very-Secret-Token"] = "42"
			ep = check.HTTPEndpointWithLabels(epName, url, labels)
			t.NewAction(s, epName, client, ep, ipFam).Run(func(a *check.Action) {
				opts := make([]string, 0, len(curlOpts)+2)
				opts = append(opts, curlOpts...)
				opts = append(opts, "-H", "X-Very-Secret-Token: 42")

				a.ExecInPod(ctx, ct.CurlCommand(ep, ipFam, opts...))

				a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
				a.ValidateFlows(ctx, ep, a.GetIngressRequirements(check.FlowParameters{}))
			})
		}
	}
}
