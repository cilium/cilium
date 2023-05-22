// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "spire") // just to avoid nil errors as well as debugging tests

func TestSpireDelegateClient_NumericIdentityToSNI(t *testing.T) {
	type args struct {
		id identity.NumericIdentity
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "convert valid numeric identity",
			args: args{
				id: 1234,
			},
			want: "1234.test.cilium.io",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log: log,
			}
			if got := s.NumericIdentityToSNI(tt.args.id); got != tt.want {
				t.Errorf("SpireDelegateClient.NumericIdentityToSNI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpireDelegateClient_SNIToNumericIdentity(t *testing.T) {
	type args struct {
		sni string
	}
	tests := []struct {
		name    string
		args    args
		want    identity.NumericIdentity
		wantErr bool
	}{
		{
			name: "convert valid SNI",
			args: args{
				sni: "1234.test.cilium.io",
			},
			want:    1234,
			wantErr: false,
		},
		{
			name: "error on convert invalid SNI under trust domain",
			args: args{
				sni: "hacker.test.cilium.io",
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "error on convert invalid SNI outside trust domain",
			args: args{
				sni: "1234.cilium.example.com",
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log: log,
			}
			got, err := s.SNIToNumericIdentity(tt.args.sni)
			if (err != nil) != tt.wantErr {
				t.Errorf("SpireDelegateClient.SNIToNumericIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SpireDelegateClient.SNIToNumericIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpireDelegateClient_sniToSPIFFEID(t *testing.T) {
	type args struct {
		id identity.NumericIdentity
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "convert valid numeric identity",
			args: args{
				id: 1234,
			},
			want: "spiffe://test.cilium.io/identity/1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log: log,
			}
			if got := s.sniToSPIFFEID(tt.args.id); got != tt.want {
				t.Errorf("SpireDelegateClient.sniToSPIFFEID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpireDelegateClient_ValidateIdentity(t *testing.T) {
	urlFor1234, _ := url.Parse("spiffe://test.cilium.io/identity/1234")
	urlFor9999, _ := url.Parse("spiffe://test.cilium.io/identity/9999")

	type args struct {
		id   identity.NumericIdentity
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "validate with correct SPIFFE ID",
			args: args{
				id: 1234,
				cert: &x509.Certificate{
					URIs: []*url.URL{urlFor1234},
				},
			},
			want: true,
		},
		{
			name: "not validate with incorrect SPIFFE ID",
			args: args{
				id: 1234,
				cert: &x509.Certificate{
					URIs: []*url.URL{urlFor9999},
				},
			},
			want: false,
		},
		{
			name: "error on validate with incorrect SPIFFE cert",
			args: args{
				id: 1234,
				cert: &x509.Certificate{
					URIs: []*url.URL{urlFor1234, urlFor9999},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "error on validate with non SPIFFE cert",
			args: args{
				id: 1234,
				cert: &x509.Certificate{
					DNSNames: []string{"test.cilium.io"},
				},
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log: log,
			}
			got, err := s.ValidateIdentity(tt.args.id, tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("SpireDelegateClient.ValidateIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SpireDelegateClient.ValidateIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpireDelegateClient_GetTrustBundle(t *testing.T) {
	someTrustBundle := x509.NewCertPool()
	someTrustBundle.AddCert(&x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.cilium.io",
		},
		IsCA: true,
	})

	tests := []struct {
		name        string
		trustBundle *x509.CertPool
		want        *x509.CertPool
		wantErr     bool
	}{
		{
			name:        "get trust bundle",
			trustBundle: someTrustBundle,
			want:        someTrustBundle,
		},
		{
			name:        "error on no trust bundle",
			trustBundle: nil,
			want:        nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log:         log,
				trustBundle: tt.trustBundle,
			}
			got, err := s.GetTrustBundle()
			if (err != nil) != tt.wantErr {
				t.Errorf("SpireDelegateClient.GetTrustBundle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SpireDelegateClient.GetTrustBundle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpireDelegateClient_GetCertificateForIdentity(t *testing.T) {
	certURL, err := url.Parse("spiffe://spiffe.cilium/identity/1234")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafCert := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{certURL},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SerialNumber: big.NewInt(1),
	}
	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafCert, leafCert, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatalf("failed to sign leaf certificate: %v", err)
	}
	leafCert, err = x509.ParseCertificate(leafCertBytes)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	leafPKCS8Key, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("failed to marshal leaf key: %v", err)
	}

	svidStore := map[string]*delegatedidentityv1.X509SVIDWithKey{
		"spiffe://test.cilium.io/identity/1234": {
			X509Svid: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "test.cilium.io",
					Path:        "/identity/1234",
				},
				CertChain: [][]byte{leafCertBytes},
			},
			X509SvidKey: leafPKCS8Key,
		},
		"spiffe://test.cilium.io/identity/2222": {
			X509Svid: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "test.cilium.io",
					Path:        "/identity/2222",
				},
				CertChain: [][]byte{},
			},
			X509SvidKey: leafPKCS8Key,
		},
		"spiffe://test.cilium.io/identity/3333": {
			X509Svid: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "test.cilium.io",
					Path:        "/identity/3333",
				},
				CertChain: [][]byte{leafCertBytes},
			},
		},
	}

	type args struct {
		id identity.NumericIdentity
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Certificate
		wantErr bool
	}{
		{
			name: "get certificate for numeric identity",
			args: args{
				id: 1234,
			},
			want: &tls.Certificate{
				Certificate: [][]byte{leafCertBytes},
				PrivateKey:  leafKey,
				Leaf:        leafCert,
			},
		},
		{
			name: "error on no certificate for numeric identity",
			args: args{
				id: 9999,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error on no certchain for numeric identity",
			args: args{
				id: 2222,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error on no private key for numeric identity",
			args: args{
				id: 3333,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log:       log,
				svidStore: svidStore,
			}
			got, err := s.GetCertificateForIdentity(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SpireDelegateClient.GetCertificateForIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SpireDelegateClient.GetCertificateForIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpireDelegateClient_SubscribeToRotatedIdentities(t *testing.T) {
	tests := []struct {
		name    string
		actions []func(t *testing.T, s *SpireDelegateClient)
		events  []certs.CertificateRotationEvent
	}{
		{
			name: "receive no event on a new ID",
			actions: []func(t *testing.T, s *SpireDelegateClient){
				func(t *testing.T, s *SpireDelegateClient) {
					s.handleX509SVIDUpdate([]*delegatedidentityv1.X509SVIDWithKey{
						{
							X509Svid: &types.X509SVID{
								Id: &types.SPIFFEID{
									TrustDomain: "test.cilium.io",
									Path:        "/identity/1234",
								},
								ExpiresAt: time.Now().Add(time.Hour).Unix(),
							},
						},
					})
				},
			},
			events: []certs.CertificateRotationEvent{},
		},
		{
			name: "receive 1 updated event",
			actions: []func(t *testing.T, s *SpireDelegateClient){
				func(t *testing.T, s *SpireDelegateClient) {
					s.handleX509SVIDUpdate([]*delegatedidentityv1.X509SVIDWithKey{
						{
							X509Svid: &types.X509SVID{
								Id: &types.SPIFFEID{
									TrustDomain: "test.cilium.io",
									Path:        "/identity/1234",
								},
								ExpiresAt: time.Now().Add(time.Hour).Unix(),
							},
						},
					})
				},
				func(t *testing.T, s *SpireDelegateClient) {
					// Update the certificate
					s.handleX509SVIDUpdate([]*delegatedidentityv1.X509SVIDWithKey{
						{
							X509Svid: &types.X509SVID{
								Id: &types.SPIFFEID{
									TrustDomain: "test.cilium.io",
									Path:        "/identity/1234",
								},
								ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
							},
						},
					})
				},
			},
			events: []certs.CertificateRotationEvent{
				{
					Identity: 1234,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SpireDelegateClient{
				cfg: SpireDelegateConfig{
					SpiffeTrustDomain: "test.cilium.io",
				},
				log:                   log,
				rotatedIdentitiesChan: make(chan certs.CertificateRotationEvent, 10),
				svidStore:             make(map[string]*delegatedidentityv1.X509SVIDWithKey),
			}
			for _, action := range tt.actions {
				action(t, s)
			}
			got := []certs.CertificateRotationEvent{}
			select {
			case event := <-s.SubscribeToRotatedIdentities():
				got = append(got, event)
			default:
				break
			}

			if !reflect.DeepEqual(got, tt.events) {
				t.Errorf("SpireDelegateClient.SubscribeToRotatedIdentities() = %v, want %v", got, tt.events)
			}
		})
	}
}
