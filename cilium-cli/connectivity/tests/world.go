// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
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
		for _, ipFam := range []features.IPFamily{features.IPFamilyV4, features.IPFamilyV6} {
			// With http, over port 80.
			httpOpts := s.rc.CurlOptions(http, ipFam, client, ct.Params())
			t.NewAction(s, fmt.Sprintf("http-to-%s-%s-%d", extTarget, ipFam, i), &client, http, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(http, ipFam, httpOpts...))
				a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
			})

			// With https, over port 443.
			httpsOpts := s.rc.CurlOptions(https, ipFam, client, ct.Params())
			t.NewAction(s, fmt.Sprintf("https-to-%s-%s-%d", extTarget, ipFam, i), &client, https, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(https, ipFam, httpsOpts...))
				a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
			})

			// With https, over port 443, index.html.
			httpsindexOpts := s.rc.CurlOptions(httpsindex, ipFam, client, ct.Params())
			t.NewAction(s, fmt.Sprintf("https-to-%s-index-%s-%d", extTarget, ipFam, i), &client, httpsindex, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(httpsindex, ipFam, httpsindexOpts...))
				a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
			})
		}

		i++
	}
}

// PodToWorld2 sends an HTTPS request to ExternalOtherTarget from random client
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
	extTarget := t.Context().Params().ExternalOtherTarget
	https := check.HTTPEndpoint(extTarget+"-https", "https://"+extTarget)

	fp := check.FlowParameters{
		DNSRequired: true,
		RSTAllowed:  true,
	}

	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		for _, ipFam := range []features.IPFamily{features.IPFamilyV4, features.IPFamilyV6} {
			// With https, over port 443.
			t.NewAction(s, fmt.Sprintf("https-%s-%s-%d", extTarget, ipFam, i), &client, https, ipFam).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(https, ipFam))
				a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
				a.ValidateMetrics(ctx, client, a.GetEgressMetricsRequirements())
			})
		}

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
		// With https, over port 443.
		t.NewAction(s, fmt.Sprintf("https-to-%s-%d", extTarget, i), &client, https, features.IPFamilyAny).Run(func(a *check.Action) {
			a.WriteDataToPod(ctx, "/tmp/test-ca.crt", caBundle)
			a.ExecInPod(ctx, ct.CurlCommand(https, features.IPFamilyAny, s.curlOpts...))
			a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
		})

		i++
	}
}

// PodToWorldWithExtraTLSIntercept is same as PodToWorldWithTLSIntercept but with extra host in middle of the test
// The goal is to make sure the secret update path is verified.
func PodToWorldWithExtraTLSIntercept(caName string, curlOpts ...string) check.Scenario {
	s := &podToWorldWithExtraTLSIntercept{
		caName:   caName,
		curlOpts: []string{"--cacert", "/tmp/test-ca.crt"}, // skip TLS verification as it will be our internal cert
	}

	s.curlOpts = append(s.curlOpts, curlOpts...)

	return s
}

type podToWorldWithExtraTLSIntercept struct {
	caName   string
	curlOpts []string
}

func (s *podToWorldWithExtraTLSIntercept) Name() string {
	return "pod-to-world-with-extra-tls-intercept"
}

func (s *podToWorldWithExtraTLSIntercept) Run(ctx context.Context, t *check.Test) {
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
	s.updateSecret(ctx, t)

	for _, client := range ct.ClientPods() {
		// With https, over port 443.
		for _, target := range []string{
			t.Context().Params().ExternalTarget,
			t.Context().Params().ExternalOtherTarget,
		} {
			https := check.HTTPEndpoint(target+"-https", "https://"+target)
			t.NewAction(s, fmt.Sprintf("https-to-%s-%d", target, i), &client, https, features.IPFamilyAny).Run(func(a *check.Action) {
				a.WriteDataToPod(ctx, "/tmp/test-ca.crt", caBundle)
				a.ExecInPod(ctx, ct.CurlCommand(https, features.IPFamilyAny, s.curlOpts...))
				a.ValidateFlows(ctx, client, a.GetEgressRequirements(fp))
			})
		}
		i++
	}
}

// updateSecret adds another hosts (e.g. ExternalOtherTarget) into the existing secrets using the same CA.
func (s *podToWorldWithExtraTLSIntercept) updateSecret(ctx context.Context, t *check.Test) {
	caCert, caKey := t.CertificateCAs()[s.caName], t.CertificateKeys()[s.caName]

	g := &csr.Generator{Validator: genkey.Validator}

	csrBytes, keyBytes, err := g.ProcessRequest(&csr.CertificateRequest{
		CN: "Cilium External Targets",
		Hosts: []string{
			t.Context().Params().ExternalTarget,      // Original target
			t.Context().Params().ExternalOtherTarget, // Additional target
		},
	})
	if err != nil {
		t.Fatalf("Unable to create CA: %s", err)
	}
	parsedCa, err := helpers.ParseCertificatePEM(caCert)
	if err != nil {
		t.Fatalf("Unable to create CSR: %s", err)
	}
	caPriv, err := helpers.ParsePrivateKeyPEM(caKey)
	if err != nil {
		t.Fatalf("Unable to parse CA key: %s", err)
	}

	signConf := &config.Signing{
		Default: &config.SigningProfile{
			Expiry: 365 * 24 * time.Hour,
			Usage:  []string{"key encipherment", "server auth", "digital signature"},
		},
	}

	sign, err := local.NewSigner(caPriv, parsedCa, signer.DefaultSigAlgo(caPriv), signConf)
	if err != nil {
		t.Fatalf("Unable to create signer: %s", err)
	}
	certBytes, err := sign.Sign(signer.SignRequest{Request: string(csrBytes)})
	if err != nil {
		t.Fatalf("Unable to sign certificate: %s", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.caName,
			Namespace: t.Context().Params().TestNamespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certBytes,
			corev1.TLSPrivateKeyKey: keyBytes,
		},
	}

	t.Infof("📜 Appending secret '%s' to namespace '%s'..", secret.Name, secret.Namespace)
	if err := ensureSecret(ctx, t.Context().Clients()[0], secret); err != nil {
		t.Fatalf("Unable to rotate secret: %s", err)
	}
}

func ensureSecret(ctx context.Context, client *k8s.Client, secret *corev1.Secret) error {
	if existing, err := client.GetSecret(ctx, secret.Namespace, secret.Name, metav1.GetOptions{}); err == nil {
		needsUpdate := false
		for k, v := range existing.Data {
			if v2, ok := secret.Data[k]; !ok || !bytes.Equal(v, v2) {
				needsUpdate = true
				break
			}
		}

		if !needsUpdate {
			return nil
		}

		_, err = client.UpdateSecret(ctx, secret.Namespace, secret, metav1.UpdateOptions{})
		return err
	}

	_, err := client.CreateSecret(ctx, secret.Namespace, secret, metav1.CreateOptions{})
	return err
}
