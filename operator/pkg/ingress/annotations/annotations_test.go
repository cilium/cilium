// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotations

import (
	"reflect"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetAnnotationServiceType(t *testing.T) {
	type args struct {
		ingress *networkingv1.Ingress
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "no service type annotation",
			args: args{
				ingress: &networkingv1.Ingress{},
			},
			want: "LoadBalancer",
		},
		{
			name: "service type annotation as LoadBalancer",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/service-type": "LoadBalancer",
						},
					},
				},
			},
			want: "LoadBalancer",
		},
		{
			name: "service type annotation as NodePort",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/service-type": "NodePort",
						},
					},
				},
			},
			want: "NodePort",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetAnnotationServiceType(tt.args.ingress); got != tt.want {
				t.Errorf("GetAnnotationServiceType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAnnotationSecureNodePort(t *testing.T) {
	type args struct {
		ingress *networkingv1.Ingress
	}
	tests := []struct {
		name    string
		args    args
		want    *uint32
		wantErr bool
	}{
		{
			name: "no secure node port annotation",
			args: args{
				ingress: &networkingv1.Ingress{},
			},
			want: nil,
		},
		{
			name: "secure node port annotation with valid value",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/secure-node-port": "1000",
						},
					},
				},
			},
			want: uint32p(1000),
		},
		{
			name: "secure node port annotation with invalid value",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/secure-node-port": "invalid-numeric-value",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAnnotationSecureNodePort(tt.args.ingress)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAnnotationSecureNodePort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAnnotationSecureNodePort() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAnnotationInsecureNodePort(t *testing.T) {
	type args struct {
		ingress *networkingv1.Ingress
	}
	tests := []struct {
		name    string
		args    args
		want    *uint32
		wantErr bool
	}{
		{
			name: "no insecure node port annotation",
			args: args{
				ingress: &networkingv1.Ingress{},
			},
			want: nil,
		},
		{
			name: "insecure node port annotation with valid value",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/insecure-node-port": "1000",
						},
					},
				},
			},
			want: uint32p(1000),
		},
		{
			name: "insecure node port annotation with invalid value",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/insecure-node-port": "invalid-numeric-value",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAnnotationInsecureNodePort(tt.args.ingress)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAnnotationSecureNodePort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAnnotationSecureNodePort() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAnnotationSSLPassthrough(t *testing.T) {
	type args struct {
		ingress *networkingv1.Ingress
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "no SSL Passthrough port annotation",
			args: args{
				ingress: &networkingv1.Ingress{},
			},
			want: false,
		},
		{
			name: "SSL Passthrough annotation present and enabled",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/tls-passthrough": "enabled",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "SSL Passthrough annotation present and disabled",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/tls-passthrough": "disabled",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "SSL Passthrough annotation present and true",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/tls-passthrough": "true",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "SSL Passthrough annotation present and false",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/tls-passthrough": "false",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "SSL Passthrough annotation present and invalid",
			args: args{
				ingress: &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"ingress.cilium.io/tls-passthrough": "invalid",
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAnnotationTLSPassthroughEnabled(tt.args.ingress)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAnnotationSecureNodePort() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func uint32p(u uint32) *uint32 {
	return &u
}
