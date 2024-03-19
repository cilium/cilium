// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// PodToWorld sends multiple HTTP(S) requests to ExternalTarget
// from each client Pods.
func PodToWorld(opts ...RetryOption) check.Scenario {
	cond := &retryCondition{}
	for _, op := range opts {
		op(cond)
	}
	return &podToWorld{rc: cond}
}

// podToWorld implements a Scenario.
type podToWorld struct {
	rc *retryCondition
}

func (s *podToWorld) Name() string {
	return "pod-to-world"
}

func (s *podToWorld) Run(ctx context.Context, t *check.Test) {
	extTarget := t.Context().Params().ExternalTarget
	http := check.HTTPEndpoint(extTarget+"-http", "http://"+extTarget)
	https := check.HTTPEndpoint(extTarget+"-https", "https://"+extTarget)
	httpsindex := check.HTTPEndpoint(extTarget+"-https-index", fmt.Sprintf("https://%s/index.html", extTarget))

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		// With http, over port 80.
		httpOpts := s.rc.CurlOptions(http, features.IPFamilyAny, client, ct.Params())
		t.NewAction(s, fmt.Sprintf("http-to-%s-%d", extTarget, i), &client, http, features.IPFamilyAny).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(http, features.IPFamilyAny, httpOpts...))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443.
		httpsOpts := s.rc.CurlOptions(https, features.IPFamilyAny, client, ct.Params())
		t.NewAction(s, fmt.Sprintf("https-to-%s-%d", extTarget, i), &client, https, features.IPFamilyAny).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(https, features.IPFamilyAny, httpsOpts...))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		// With https, over port 443, index.html.
		httpsindexOpts := s.rc.CurlOptions(httpsindex, features.IPFamilyAny, client, ct.Params())
		t.NewAction(s, fmt.Sprintf("https-to-%s-index-%d", extTarget, i), &client, httpsindex, features.IPFamilyAny).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(httpsindex, features.IPFamilyAny, httpsindexOpts...))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}

// PodToWorld2 sends an HTTPS request to cilium.io from from random client
// Pods.
func PodToWorld2() check.Scenario {
	return &podToWorld2{}
}

// podToWorld2 implements a Scenario.
type podToWorld2 struct{}

func (s *podToWorld2) Name() string {
	return "pod-to-world-2"
}

func (s *podToWorld2) Run(ctx context.Context, t *check.Test) {
	https := check.HTTPEndpoint("cilium-io-https", "https://cilium.io.")

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-cilium-io-%d", i), &client, https, features.IPFamilyAny).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(https, features.IPFamilyAny))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
			a.ValidateMetrics(ctx, client, a.GetEgressMetricsRequirements())
		})

		i++
	}
}

// PodToWorldWithTLSIntercept sends an HTTPS request to one.one.one.one (default value of ExternalTarget) from from random client
func PodToWorldWithTLSIntercept(curlOpts ...string) check.Scenario {
	s := &podToWorldWithTLSIntercept{
		curlOpts: []string{"--cacert", "/tmp/test-ca.crt"}, // skip TLS verification as it will be our internal cert
	}

	s.curlOpts = append(s.curlOpts, curlOpts...)

	return s
}

// podToWorldWithTLSIntercept implements a Scenario.
type podToWorldWithTLSIntercept struct {
	curlOpts []string
}

func (s *podToWorldWithTLSIntercept) Name() string {
	return "pod-to-world-with-tls-intercept"
}

func (s *podToWorldWithTLSIntercept) Run(ctx context.Context, t *check.Test) {
	extTarget := t.Context().Params().ExternalTarget

	https := check.HTTPEndpoint(extTarget+"-https", "https://"+extTarget)

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	var caBundle []byte
	// join all the CA certs into a single file
	for _, caFile := range t.CertificateCAs() {
		caBundle = append(caBundle, caFile...)
		caBundle = append(caBundle, '\n')
	}

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-to-%s-%d", extTarget, i), &client, https, features.IPFamilyAny).Run(func(a *check.Action) {
			a.WriteDataToPod(ctx, "/tmp/test-ca.crt", caBundle)
			a.ExecInPod(ctx, ct.CurlCommand(https, features.IPFamilyAny, s.curlOpts...))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}
