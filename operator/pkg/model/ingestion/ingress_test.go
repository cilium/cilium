// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	baseIngressTestDataDir = "testdata/ingress"
)

var defaultSecretNamespace = "default-secret-namespace"

var defaultSecretName = "default-secret-name"

type testcase struct {
	defaultSecret  bool
	enforceHTTPS   bool
	requestTimeout time.Duration
}

func TestIngress(t *testing.T) {
	tests := map[string]testcase{
		"conformance default backend test":                                         {},
		"conformance default backend (legacy annotation) test":                     {},
		"conformance default backend (legacy + new) test":                          {},
		"cilium test ingress without http rules":                                   {},
		"conformance host rules test":                                              {},
		"conformance host rules test without SecretName":                           {},
		"conformance path rules test":                                              {},
		"cilium test ingress":                                                      {},
		"cilium test ingress without SecretName":                                   {},
		"cilium test ingress with NodePort":                                        {},
		"cilium test ingress with NodePort without SecretName":                     {},
		"conformance default backend test with default secret":                     {defaultSecret: true},
		"conformance default backend (legacy annotation) test with default secret": {defaultSecret: true},
		"conformance default backend (legacy + new) test with default secret":      {defaultSecret: true},
		"conformance host rules test with default secret":                          {defaultSecret: true},
		"conformance host rules test with default secret without SecretName":       {defaultSecret: true},
		"conformance path rules test with default secret":                          {defaultSecret: true},
		"cilium test ingress with default secret":                                  {defaultSecret: true},
		"cilium test ingress with default secret without SecretName":               {defaultSecret: true},
		"cilium test ingress with NodePort with default secret":                    {defaultSecret: true},
		"cilium test ingress with NodePort with default secret without SecretName": {defaultSecret: true},
		"cilium multiple path types":                                               {},
		"force-https annotation present and enabled":                               {},
		"force-https annotation present and enabled, enforceHTTPS enabled":         {enforceHTTPS: true},
		"force-https annotation present and disabled, enforceHTTPS enabled":        {enforceHTTPS: true},
		"force-https annotation present and disabled, enforceHTTPS disabled":       {},
		"force-https annotation not present, enforceHTTPS enabled":                 {enforceHTTPS: true},
		"request-timeout flag present with no annotation":                          {requestTimeout: time.Second * 10},
		"request-timeout annotation present":                                       {},
		"request-timeout annotation present but invalid":                           {},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			input := networkingv1.Ingress{}
			readInput(t, fmt.Sprintf("%s/%s/input-ingress.yaml", baseIngressTestDataDir, rewriteTestName(name)), &input)
			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/output-listeners.yaml", baseIngressTestDataDir, rewriteTestName(name)), &expected)

			var listeners []model.HTTPListener
			if tc.defaultSecret {
				listeners = Ingress(logger, input, defaultSecretNamespace, defaultSecretName, tc.enforceHTTPS, 80, 443, tc.requestTimeout)
			} else {
				listeners = Ingress(logger, input, "", "", tc.enforceHTTPS, 80, 443, tc.requestTimeout)
			}

			assert.Equal(t, expected, listeners, "Listeners did not match")
		})
	}
}

type passthruTestcase struct{}

func TestIngressPassthrough(t *testing.T) {
	tests := map[string]passthruTestcase{
		"Cilium test ingress with SSL Passthrough":                                 {},
		"Cilium test ingress with SSL Passthrough, no host set":                    {},
		"Cilium test ingress with SSL Passthrough, host but no rule":               {},
		"Cilium test ingress with SSL Passthrough, prefix path rule":               {},
		"Cilium test ingress with SSL Passthrough and default backend":             {},
		"Cilium test ingress with SSL Passthrough, multiple path rules, one valid": {},
		"Cilium test ingress with SSL Passthrough, Nodeport Service annotations":   {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			input := networkingv1.Ingress{}
			readInput(t, fmt.Sprintf("%s/%s/input-ingress.yaml", baseIngressTestDataDir, rewriteTestName(name)), &input)
			expected := []model.TLSPassthroughListener{}
			readOutput(t, fmt.Sprintf("%s/%s/output-listeners.yaml", baseIngressTestDataDir, rewriteTestName(name)), &expected)

			listeners := IngressPassthrough(logger, input, 443)

			assert.Equal(t, expected, listeners, "Listeners did not match")
		})
	}
}
