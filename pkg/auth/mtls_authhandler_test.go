// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/auth/certs"
	"github.com/cilium/cilium/pkg/identity"
)

var (
	id1000 = identity.NumericIdentity(1000)
	id1001 = identity.NumericIdentity(1001)
	idbad1 = identity.NumericIdentity(9999)
)

type fakeCertificateProvider struct {
	certMap    map[string]*x509.Certificate
	privkeyMap map[string]*ecdsa.PrivateKey
	caPool     *x509.CertPool
}

func (f *fakeCertificateProvider) GetTrustBundle() (*x509.CertPool, error) {
	return f.caPool, nil
}

func (f *fakeCertificateProvider) GetCertificateForIdentity(id identity.NumericIdentity) (*tls.Certificate, error) {
	uriSAN := "spiffe://spiffe.cilium/identity/" + id.String()
	cert, ok := f.certMap[uriSAN]
	if !ok {
		return nil, fmt.Errorf("no certificate for %s", uriSAN)
	}

	// convert the x509 cert to tls cert
	certBytes := cert.Raw
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  f.privkeyMap[uriSAN],
		Leaf:        cert,
	}
	return &tlsCert, nil
}

func (f *fakeCertificateProvider) ValidateIdentity(id identity.NumericIdentity, cert *x509.Certificate) (bool, error) {
	for _, uri := range cert.URIs {
		if uri.String() == fmt.Sprintf("spiffe://spiffe.cilium/identity/%d", id) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeCertificateProvider) NumericIdentityToSNI(id identity.NumericIdentity) string {
	return id.String() + "." + "spiffe.cilium"
}

func (f *fakeCertificateProvider) SNIToNumericIdentity(sni string) (identity.NumericIdentity, error) {
	suffix := "." + "spiffe.cilium"
	if !strings.HasSuffix(sni, suffix) {
		return 0, fmt.Errorf("SNI %s does not belong to our trust domain", sni)
	}

	idStr := strings.TrimSuffix(sni, suffix)
	return identity.ParseNumericIdentity(idStr)
}

func (f *fakeCertificateProvider) SubscribeToRotatedIdentities() <-chan certs.CertificateRotationEvent {
	return nil
}

func generateTestCertificates(t *testing.T) (map[string]*x509.Certificate, map[string]*ecdsa.PrivateKey, *x509.CertPool) {
	caPool := x509.NewCertPool()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caCert := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "ca"},
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
	}
	// sign the CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to sign CA certificate: %v", err)
	}
	caCert, err = x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	caPool.AddCert(caCert)

	// sign two SPIFFE like certificates
	leafCerts := make(map[string]*x509.Certificate)
	leafPrivKeys := make(map[string]*ecdsa.PrivateKey)

	for i := 1000; i <= 1001; i++ {
		certURL, err := url.Parse(fmt.Sprintf("spiffe://spiffe.cilium/identity/%d", i))
		if err != nil {
			t.Fatalf("failed to parse URL: %v", err)
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate leaf key: %v", err)
		}
		leafCert := &x509.Certificate{
			NotAfter:     time.Now().Add(time.Hour),
			URIs:         []*url.URL{certURL},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			SerialNumber: big.NewInt(int64(i)),
		}
		leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafCert, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("failed to sign leaf certificate: %v", err)
		}
		leafCert, err = x509.ParseCertificate(leafCertBytes)
		if err != nil {
			t.Fatalf("failed to parse leaf certificate: %v", err)
		}
		leafCerts[certURL.String()] = leafCert
		leafPrivKeys[certURL.String()] = leafKey
	}

	return leafCerts, leafPrivKeys, caPool
}

func Test_mtlsAuthHandler_verifyPeerCertificate(t *testing.T) {
	certMap, keyMap, caPool := generateTestCertificates(t)
	certMapOtherCA, _, _ := generateTestCertificates(t)
	type args struct {
		id             *identity.NumericIdentity
		caBundle       *x509.CertPool
		verifiedChains [][]*x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    *time.Time
		wantErr bool
	}{
		{
			name: "valid certificate with SNI to match identity",
			args: args{
				id:             &id1000,
				caBundle:       caPool,
				verifiedChains: [][]*x509.Certificate{{certMap["spiffe://spiffe.cilium/identity/1000"]}},
			},
			want:    &certMap["spiffe://spiffe.cilium/identity/1000"].NotAfter,
			wantErr: false,
		},
		{
			name: "valid certificate with no identity provided",
			args: args{
				id:             nil,
				caBundle:       caPool,
				verifiedChains: [][]*x509.Certificate{{certMap["spiffe://spiffe.cilium/identity/1000"]}},
			},
			want:    &certMap["spiffe://spiffe.cilium/identity/1000"].NotAfter,
			wantErr: false,
		},
		{
			name: "error on invalid certificate because incorrect identity provided",
			args: args{
				id:             &id1001,
				caBundle:       caPool,
				verifiedChains: [][]*x509.Certificate{{certMap["spiffe://spiffe.cilium/identity/1000"]}},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error on invalid certificate signed by other CA",
			args: args{
				id:             &id1000,
				caBundle:       caPool,
				verifiedChains: [][]*x509.Certificate{{certMapOtherCA["spiffe://spiffe.cilium/identity/1000"]}},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error on invalid certificate signed by other CA with no identity provided",
			args: args{
				id:             nil,
				caBundle:       caPool,
				verifiedChains: [][]*x509.Certificate{{certMapOtherCA["spiffe://spiffe.cilium/identity/1000"]}},
			},
			want:    nil,
			wantErr: true,
		}, {
			name: "error on no certificates in verifiedChains",
			args: args{
				id:             nil,
				caBundle:       caPool,
				verifiedChains: [][]*x509.Certificate{},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error on empty caBundle provided",
			args: args{
				id:             nil,
				caBundle:       x509.NewCertPool(),
				verifiedChains: [][]*x509.Certificate{{certMapOtherCA["spiffe://spiffe.cilium/identity/1000"]}},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mtlsAuthHandler{
				cfg:  MTLSConfig{MTLSListenerPort: 1234},
				log:  log,
				cert: &fakeCertificateProvider{certMap: certMap, caPool: caPool, privkeyMap: keyMap},
			}
			got, err := m.verifyPeerCertificate(tt.args.id, tt.args.caBundle, tt.args.verifiedChains)
			if (err != nil) != tt.wantErr {
				t.Errorf("mtlsAuthHandler.verifyPeerCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mtlsAuthHandler.verifyPeerCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mtlsAuthHandler_GetCertificateForIncomingConnection(t *testing.T) {
	certMap, keyMap, caPool := generateTestCertificates(t)
	type args struct {
		info *tls.ClientHelloInfo
	}
	tests := []struct {
		name    string
		args    args
		wantURI string
		wantErr bool
	}{
		{
			name: "valid certificate with SNI to match identity",
			args: args{
				info: &tls.ClientHelloInfo{
					ServerName: "1000.spiffe.cilium",
				},
			},
			wantURI: "spiffe://spiffe.cilium/identity/1000",
			wantErr: false,
		},
		{
			name: "no certificate for non existing identity",
			args: args{
				info: &tls.ClientHelloInfo{
					ServerName: "9999.spiffe.cilium",
				},
			},
			wantErr: true,
		},
		{
			name: "no certificate for random non existing domain",
			args: args{
				info: &tls.ClientHelloInfo{
					ServerName: "www.example.com",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mtlsAuthHandler{
				cfg:  MTLSConfig{MTLSListenerPort: 1234},
				log:  log,
				cert: &fakeCertificateProvider{certMap: certMap, caPool: caPool, privkeyMap: keyMap},
			}
			got, err := m.GetCertificateForIncomingConnection(tt.args.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("mtlsAuthHandler.GetCertificateForIncomingConnection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Leaf == nil {
					t.Errorf("mtlsAuthHandler.GetCertificateForIncomingConnection() leaf certificate is nil")
				}
				if len(got.Leaf.URIs) == 0 {
					t.Errorf("mtlsAuthHandler.GetCertificateForIncomingConnection() leaf certificate has no URIs")
				}
				gotURI := got.Leaf.URIs[0].String()
				if !reflect.DeepEqual(gotURI, tt.wantURI) {
					t.Errorf("mtlsAuthHandler.GetCertificateForIncomingConnection() = %v, want %v", got, tt.wantURI)
				}
			}

		})
	}
}

func Test_mtlsAuthHandler_authenticate(t *testing.T) {
	certMap, keyMap, caPool := generateTestCertificates(t)

	tls := &mtlsAuthHandler{
		cfg:  MTLSConfig{MTLSListenerPort: getRandomOpenPort(t)},
		log:  log,
		cert: &fakeCertificateProvider{certMap: certMap, caPool: caPool, privkeyMap: keyMap},
	}
	tls.onStart(context.Background())
	defer tls.onStop(context.Background())

	var lowestExpirationTime time.Time
	for _, cert := range certMap {
		if lowestExpirationTime.IsZero() || cert.NotAfter.Before(lowestExpirationTime) {
			lowestExpirationTime = cert.NotAfter
		}
	}

	type args struct {
		ar *authRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *authResponse
		wantErr bool
	}{
		{
			name: "authenticate two valid identities",
			args: args{
				ar: &authRequest{
					localIdentity:  id1000,
					remoteIdentity: id1001,
					remoteNodeIP:   GetLoopBackIP(t),
				},
			},
			want: &authResponse{
				expirationTime: lowestExpirationTime,
			},
		},
		{
			name: "error on authenticate when remote identity is not valid",
			args: args{
				ar: &authRequest{
					localIdentity:  id1000,
					remoteIdentity: idbad1,
					remoteNodeIP:   GetLoopBackIP(t),
				},
			},
			wantErr: true,
		},
		{
			name: "error on  authenticate when local identity is not valid",
			args: args{
				ar: &authRequest{
					localIdentity:  idbad1,
					remoteIdentity: id1001,
					remoteNodeIP:   GetLoopBackIP(t),
				},
			},
			wantErr: true,
		},
		{
			name: "error on authenticate when auth request is bad",
			args: args{
				ar: &authRequest{
					localIdentity: id1000,
					// all other fields are intentionally left blank
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tls.authenticate(tt.args.ar)
			if (err != nil) != tt.wantErr {
				t.Errorf("mtlsAuthHandler.authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mtlsAuthHandler.authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getRandomOpenPort(t *testing.T) int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to get random open port: %v", err)
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr.Port
}

func GetLoopBackIP(t *testing.T) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("failed to get interface addresses: %v", err)
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.IsLoopback() {
			return ipnet.IP.String()
		}
	}

	t.Fatalf("failed to get loopback IP")
	return ""
}
