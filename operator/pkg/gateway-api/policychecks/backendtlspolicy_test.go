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
			name: "CACertificateRef exists, has right key",
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
			statusDiff := cmp.Diff(b.BackendTLSPolicy.Status, tt.wantStatus, cmpIgnoreFields...)
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
