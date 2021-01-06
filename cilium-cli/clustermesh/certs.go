// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clustermesh

import (
	"time"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	serverTLS = "clustermesh-apiserver-server-cert"
	adminTLS  = "clustermesh-apiserver-admin-cert"
	serverCA  = "clustermesh-apiserver-ca-cert"
	clientTLS = "cilium-etcd-client-tls"
)

func generateCertificates(namespace string) (map[string]map[string][]byte, error) {
	ca, _, caKey, err := initca.New(getCA())
	if err != nil {
		return nil, err
	}

	serverCert, serverKey, err := generateCertificate(ca, caKey, serverTLS, getServerCertReq(namespace))
	if err != nil {
		return nil, err
	}

	adminCert, adminKey, err := generateCertificate(ca, caKey, adminTLS, getAdminCertReq(namespace))
	if err != nil {
		return nil, err
	}

	clientCert, clientKey, err := generateCertificate(ca, caKey, clientTLS, getEtcdClientCertReq())
	if err != nil {
		return nil, err
	}

	return map[string]map[string][]byte{
		serverTLS: {
			"tls.key": serverKey,
			"tls.crt": serverCert,
		},
		serverCA: {
			"ca.crt": ca,
		},
		adminTLS: {
			"tls.key": adminKey,
			"tls.crt": adminCert,
		},
		clientTLS: {
			"etcd-client.key":    clientKey,
			"etcd-client-ca.crt": ca,
			"etcd-client.crt":    clientCert,
		},
	}, nil
}

// getCA returns the certificate request for Cilium-etcd
func getCA() *csr.CertificateRequest {
	return &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "San Francisco",
				L:  "CA",
				O:  "Cilium",
				OU: "ClusterMesh",
			},
		},
		KeyRequest: &csr.KeyRequest{
			A: "rsa",
			S: 2048,
		},
		CN: "clustermesh-apiserver CA",
	}
}

// getServerCertReq returns the server certificate requests for the given
// namespace.
func getServerCertReq(namespace string) *csr.CertificateRequest {
	return &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "San Francisco",
				L:  "CA",
			},
		},
		KeyRequest: &csr.KeyRequest{
			A: "rsa",
			S: 2048,
		},
		Hosts: []string{
			"clustermesh-apiserver.cilium.io",
			"*.mesh.cilium.io",
			"localhost",
			"127.0.0.1",
		},
		CN: "etcd server",
	}
}

func getAdminCertReq(namespace string) *csr.CertificateRequest {
	return &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "San Francisco",
				L:  "CA",
			},
		},
		KeyRequest: &csr.KeyRequest{
			A: "rsa",
			S: 2048,
		},
		Hosts: []string{
			"localhost",
			"127.0.0.1",
		},
		CN: "root",
	}
}

// getEtcdClientCertReq returns the client certificate request.
func getEtcdClientCertReq() *csr.CertificateRequest {
	return &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "San Francisco",
				L:  "CA",
			},
		},
		KeyRequest: &csr.KeyRequest{
			A: "rsa",
			S: 2048,
		},
		Hosts: []string{""},
		CN:    "etcd client",
	}
}

// getDefaultConfig returns the signing configuration for all profiles going
// to be used, (server, client and peer)
func getDefaultConfig() *config.Signing {
	return &config.Signing{
		Default: &config.SigningProfile{
			Expiry: 5 * 365 * 24 * time.Hour,
		},
		Profiles: map[string]*config.SigningProfile{
			serverTLS: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage: []string{
					"signing",
					"key encipherment",
					"server auth",
					"client auth",
				},
			},
			adminTLS: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage: []string{
					"signing",
					"key encipherment",
					"server auth",
					"client auth",
				},
			},
			clientTLS: {
				Expiry: 5 * 365 * 24 * time.Hour,
				Usage: []string{
					"signing",
					"key encipherment",
					"server auth",
					"client auth",
				},
			},
		},
	}
}

// generateCertificate returns the certificate and key generated for the given
// profile and certificate request.
func generateCertificate(ca, caKey []byte, profile string, certReq *csr.CertificateRequest) (certBytes []byte, keyBytes []byte, err error) {
	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, keyBytes, err := g.ProcessRequest(certReq)
	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, nil, err
	}
	priv, err := helpers.ParsePrivateKeyPEM(caKey)
	if err != nil {
		return nil, nil, err
	}
	s, err := local.NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), getDefaultConfig())
	if err != nil {
		return nil, nil, err
	}
	signReq := signer.SignRequest{
		Request: string(csrBytes),
		Profile: profile,
	}
	certBytes, err = s.Sign(signReq)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, keyBytes, nil
}
