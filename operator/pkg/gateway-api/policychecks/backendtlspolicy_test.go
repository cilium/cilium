// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policychecks

import (
	"context"
	"log/slog"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"
)

var cmpIgnoreFields = []cmp.Option{
	cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime"),
}

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))

	return scheme
}

var caCert = `-----BEGIN CERTIFICATE-----
MIIENDCCApygAwIBAgIRAKD/BLFBfwKIZ0WGrHtTH6gwDQYJKoZIhvcNAQELBQAw
dzEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSYwJAYDVQQLDB10YW1t
YWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTEtMCsGA1UEAwwkbWtjZXJ0IHRhbW1h
Y2hAZmVkb3JhLmxhbiAoVGFtIE1hY2gpMB4XDTIzMDIyMTExMDg0M1oXDTI1MDUy
MTEyMDg0M1owUTEnMCUGA1UEChMebWtjZXJ0IGRldmVsb3BtZW50IGNlcnRpZmlj
YXRlMSYwJAYDVQQLDB10YW1tYWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIZy+0JRVjqpWgeq2dP+1oliO4A
CcZnMg4tSqPalhDQL6Mf68HYLfizyJIpRzMJ905rYd0AcmXmu/g0Eo8ykHxFDz5T
sePs2XQng8MN4azsRmm1l4f74ovawQzQcb822QP1CS6ILZ3VtwNjRh2nAwthYBMo
CkngDGeQ8Gl0tjHLFnBdTdSwQRmE2jtDBcAgyEGpq+6ReYt+/47nNn7dCftsVqhE
BYr9XH3itefHmsbfj7zWFbptdko7q9lMHwnBd+0hd40MmJIXMZrOGGFZjawJDBqS
sBq2Q3l6XQz8X7P/GA8Dn8h4w3rppmiaN7LOmGXeki3xX2wqnM+0s6aZYZsCAwEA
AaNhMF8wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB8GA1Ud
IwQYMBaAFGQ2DB06CdQFQBsYPye0NBwErUNEMBcGA1UdEQQQMA6CDHVuaXR0ZXN0
LmNvbTANBgkqhkiG9w0BAQsFAAOCAYEArtHdKWXR6aELpfal17biabCPvIF9j6nw
uDzcdMYQLrXm8M+NHe8x3dpI7u3lltO+dzLng+nVKQOR3alQACSmRD9c7ie8eT5d
7zKOTk6keY195I1wVV4jbNLbNWa9y4RJQRTvBLAvAP9NVtUw2Q/w/ErUTqSyz+ob
dwnt4gYCw6dGnluLxlfF34DB9KflvVNSnkyMB/gsB4A3r1GPOIo0Gyf74ig3FWrS
wHYKnBbtZfYO0JV0LCoPyHe8g0XajZe8DCbP/E6SmlTNAmJESVjigTTcIBAkFI+n
toBAdxfhjKUGaClOHS29cpaiynjSayGm4RkHkx7mcAua9lWPf7pSa3mCcFb+wFr3
ABkHDPJH2acfaUK1vgKTgOwcG/6KA820/PraoSihLaPK/A7eg77r1EeYpt0Neppb
XjvUp3YmVlIMZXPzrjOsastoDSrsygj5jdVtm4Pslv9nPhzDrBjlZpEJScW4Jlb+
6wtd7p03UDBSKfTbVROVAe5mvJvA0hoS
-----END CERTIFICATE-----
`

func TestBackendTLSPolicyInput_ValidateSpec(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	controllerName := gatewayv1.GatewayController("io.cilium/gateway-controller")

	echoaAncestorRef := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Name:      "echo-a",
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
	}

	backendTLSPolicyTypeMeta := metav1.TypeMeta{
		APIVersion: gatewayv1.GroupVersion.Group + "/" + gatewayv1.GroupVersion.Version,
		Kind:       "BackendTLSPolicy",
	}

	tests := []struct {
		name       string // description of this test case
		btlsp      *gatewayv1.BackendTLSPolicy
		wantStatus gatewayv1.PolicyStatus
		caCert     *corev1.ConfigMap
		wantErr    bool
		wantValid  bool
	}{
		{
			name: "Both CACertificateRefs and WellKnownCACertificates set",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("echo-ca"),
							},
						},
						WellKnownCACertificates: ptr.To[gatewayv1.WellKnownCACertificatesType]("System"),
					},
				},
			},
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: []gatewayv1.PolicyAncestorStatus{
					{
						AncestorRef:    echoaAncestorRef,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:    "Accepted",
								Status:  "False",
								Reason:  "Invalid",
								Message: "Cannot have both CACertificateRefs and wellKnownCACertificates set",
							},
							{
								Type:    "ResolvedRefs",
								Status:  "False",
								Reason:  "Invalid",
								Message: "Cannot have both CACertificateRefs and wellKnownCACertificates set",
							},
						},
					},
				},
			},
		},
		{
			name: "More than one CACertificateRef",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("echo-ca"),
							},
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("Secret"),
								Name:  gatewayv1.ObjectName("someother-ca"),
							},
						},
					},
				},
			},
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: []gatewayv1.PolicyAncestorStatus{
					{
						AncestorRef:    echoaAncestorRef,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:    "Accepted",
								Status:  "False",
								Reason:  "Invalid",
								Message: "Having more than one CA Certificate Ref is not supported",
							},
							{
								Type:    "ResolvedRefs",
								Status:  "False",
								Reason:  "Invalid",
								Message: "Having more than one CA Certificate Ref is not supported",
							},
						},
					},
				},
			},
		},
		{
			name: "CACertificateRef is not a ConfigMap",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("Secret"),
								Name:  gatewayv1.ObjectName("someother-ca"),
							},
						},
					},
				},
			},
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: []gatewayv1.PolicyAncestorStatus{
					{
						AncestorRef:    echoaAncestorRef,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:    "Accepted",
								Status:  "False",
								Reason:  "NoValidCACertificate",
								Message: "Only ConfigMaps are supported for CA Certificate Refs",
							},
							{
								Type:    "ResolvedRefs",
								Status:  "False",
								Reason:  "InvalidKind",
								Message: "Only ConfigMaps are supported for CA Certificate Refs",
							},
						},
					},
				},
			},
		},
		{
			name: "CACertificateRef does not exist",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("echo-ca"),
							},
						},
					},
				},
			},
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: []gatewayv1.PolicyAncestorStatus{
					{
						AncestorRef:    echoaAncestorRef,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:    "Accepted",
								Status:  "False",
								Reason:  "NoValidCACertificate",
								Message: "CA Certificate does not exist: default/echo-ca",
							},
							{
								Type:    "ResolvedRefs",
								Status:  "False",
								Reason:  "InvalidCACertificateRef",
								Message: "CA Certificate does not exist: default/echo-ca",
							},
						},
					},
				},
			},
		},
		{
			name: "CACertificateRef exists, not the right key",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("echo-ca"),
							},
						},
					},
				},
			},
			caCert: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "echo-ca",
					Namespace: "default",
				},
				Data: map[string]string{
					"someotherkey": "data",
				},
			},
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: []gatewayv1.PolicyAncestorStatus{
					{
						AncestorRef:    echoaAncestorRef,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:    "Accepted",
								Status:  "False",
								Reason:  "NoValidCACertificate",
								Message: "CA Certificate ConfigMap does not contain a `ca.crt` key",
							},
							{
								Type:    "ResolvedRefs",
								Status:  "False",
								Reason:  "InvalidCACertificateRef",
								Message: "CA Certificate ConfigMap does not contain a `ca.crt` key",
							},
						},
					},
				},
			},
		},
		{
			name: "CACertificateRef exists, has right key, but no cert",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("echo-ca"),
							},
						},
					},
				},
			},
			caCert: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "echo-ca",
					Namespace: "default",
				},
				Data: map[string]string{
					"ca.crt": "data",
				},
			},
			wantValid: false,
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: []gatewayv1.PolicyAncestorStatus{
					{
						AncestorRef:    echoaAncestorRef,
						ControllerName: controllerName,
						Conditions: []metav1.Condition{
							{
								Type:    "Accepted",
								Status:  "False",
								Reason:  "NoValidCACertificate",
								Message: "CA Certificate ConfigMap does not contain at least one valid PEM-encoded certificate",
							},
							{
								Type:    "ResolvedRefs",
								Status:  "False",
								Reason:  "InvalidCACertificateRef",
								Message: "CA Certificate ConfigMap does not contain at least one valid PEM-encoded certificate",
							},
						},
					},
				},
			},
		},
		{
			name: "CACertificateRef exists, has right key, has cert",
			btlsp: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-both-set",
					Namespace: "default",
				},
				TypeMeta: backendTLSPolicyTypeMeta,
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("echo-ca"),
							},
						},
					},
				},
			},
			caCert: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "echo-ca",
					Namespace: "default",
				},
				Data: map[string]string{
					"ca.crt": caCert,
				},
			},
			wantValid: true,
			wantStatus: gatewayv1.PolicyStatus{
				Ancestors: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientBuilder := fake.NewClientBuilder().
				WithStatusSubresource(&corev1.ConfigMap{}).
				WithStatusSubresource(&gatewayv1.BackendTLSPolicy{})
			if tt.caCert != nil {
				clientBuilder.WithObjects(tt.caCert)
			}

			if tt.btlsp != nil {
				clientBuilder.WithObjects(tt.btlsp)
			}

			clientBuilder.WithScheme(testScheme())
			c := clientBuilder.Build()

			b := BackendTLSPolicyInput{
				Client:           c,
				BackendTLSPolicy: tt.btlsp,
			}
			gotvalid, gotErr := b.ValidateSpec(context.Background(), logger, echoaAncestorRef)
			statusDiff := cmp.Diff(tt.wantStatus, b.BackendTLSPolicy.Status, cmpIgnoreFields...)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ValidateSpec() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ValidateSpec() succeeded unexpectedly")
			}
			if gotvalid != tt.wantValid {
				t.Fatalf("Validity did not match expectations, want: %t, got %t", tt.wantValid, gotvalid)
			}
			if len(statusDiff) != 0 {
				t.Fatalf("Status did not match\n %s", statusDiff)
			}
		})
	}
}
