/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package options

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/version"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	. "k8s.io/apiserver/pkg/server"
	utilflag "k8s.io/apiserver/pkg/util/flag"
	"k8s.io/client-go/discovery"
	restclient "k8s.io/client-go/rest"
)

func setUp(t *testing.T) Config {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)

	config := NewConfig(codecs)
	config.RequestContextMapper = genericapirequest.NewRequestContextMapper()

	return *config
}

type TestCertSpec struct {
	host       string
	names, ips []string // in certificate
}

type NamedTestCertSpec struct {
	TestCertSpec
	explicitNames []string // as --tls-sni-cert-key explicit names
}

func TestGetNamedCertificateMap(t *testing.T) {
	tests := []struct {
		certs         []NamedTestCertSpec
		explicitNames []string
		expected      map[string]int // name to certs[*] index
		errorString   string
	}{
		{
			// empty certs
			expected: map[string]int{},
		},
		{
			// only one cert
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
					},
				},
			},
			expected: map[string]int{
				"test.com": 0,
			},
		},
		{
			// ips are ignored
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
						ips:  []string{"1.2.3.4"},
					},
				},
			},
			expected: map[string]int{
				"test.com": 0,
			},
		},
		{
			// two certs with the same name
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
					},
				},
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
					},
				},
			},
			expected: map[string]int{
				"test.com": 0,
			},
		},
		{
			// two certs with different names
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test2.com",
					},
				},
				{
					TestCertSpec: TestCertSpec{
						host: "test1.com",
					},
				},
			},
			expected: map[string]int{
				"test1.com": 1,
				"test2.com": 0,
			},
		},
		{
			// two certs with the same name, explicit trumps
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
					},
				},
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
					},
					explicitNames: []string{"test.com"},
				},
			},
			expected: map[string]int{
				"test.com": 1,
			},
		},
		{
			// certs with partial overlap; ips are ignored
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host:  "a",
						names: []string{"a.test.com", "test.com"},
					},
				},
				{
					TestCertSpec: TestCertSpec{
						host:  "b",
						names: []string{"b.test.com", "test.com"},
					},
				},
			},
			expected: map[string]int{
				"a": 0, "b": 1,
				"a.test.com": 0, "b.test.com": 1,
				"test.com": 0,
			},
		},
		{
			// wildcards
			certs: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host:  "a",
						names: []string{"a.test.com", "test.com"},
					},
					explicitNames: []string{"*.test.com", "test.com"},
				},
				{
					TestCertSpec: TestCertSpec{
						host:  "b",
						names: []string{"b.test.com", "test.com"},
					},
					explicitNames: []string{"dev.test.com", "test.com"},
				}},
			expected: map[string]int{
				"test.com":     0,
				"*.test.com":   0,
				"dev.test.com": 1,
			},
		},
	}

NextTest:
	for i, test := range tests {
		var namedTLSCerts []NamedTLSCert
		bySignature := map[string]int{} // index in test.certs by cert signature
		for j, c := range test.certs {
			cert, err := createTestTLSCerts(c.TestCertSpec)
			if err != nil {
				t.Errorf("%d - failed to create cert %d: %v", i, j, err)
				continue NextTest
			}

			namedTLSCerts = append(namedTLSCerts, NamedTLSCert{
				TLSCert: cert,
				Names:   c.explicitNames,
			})

			sig, err := certSignature(cert)
			if err != nil {
				t.Errorf("%d - failed to get signature for %d: %v", i, j, err)
				continue NextTest
			}
			bySignature[sig] = j
		}

		certMap, err := GetNamedCertificateMap(namedTLSCerts)
		if err == nil && len(test.errorString) != 0 {
			t.Errorf("%d - expected no error, got: %v", i, err)
		} else if err != nil && err.Error() != test.errorString {
			t.Errorf("%d - expected error %q, got: %v", i, test.errorString, err)
		} else {
			got := map[string]int{}
			for name, cert := range certMap {
				x509Certs, err := x509.ParseCertificates(cert.Certificate[0])
				assert.NoError(t, err, "%d - invalid certificate for %q", i, name)
				assert.True(t, len(x509Certs) > 0, "%d - expected at least one x509 cert in tls cert for %q", i, name)
				got[name] = bySignature[x509CertSignature(x509Certs[0])]
			}

			assert.EqualValues(t, test.expected, got, "%d - wrong certificate map", i)
		}
	}
}

func TestServerRunWithSNI(t *testing.T) {
	tests := map[string]struct {
		Cert              TestCertSpec
		SNICerts          []NamedTestCertSpec
		ExpectedCertIndex int

		// passed in the client hello info, "localhost" if unset
		ServerName string

		// optional ip or hostname to pass to NewLoopbackClientConfig
		LoopbackClientBindAddressOverride string
		ExpectLoopbackClientError         bool
	}{
		"only one cert": {
			Cert: TestCertSpec{
				host: "localhost",
				ips:  []string{"127.0.0.1"},
			},
			ExpectedCertIndex: -1,
		},
		"cert with multiple alternate names": {
			Cert: TestCertSpec{
				host:  "localhost",
				names: []string{"test.com"},
				ips:   []string{"127.0.0.1"},
			},
			ExpectedCertIndex: -1,
			ServerName:        "test.com",
		},
		"one SNI and the default cert with the same name": {
			Cert: TestCertSpec{
				host: "localhost",
				ips:  []string{"127.0.0.1"},
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "localhost",
					},
				},
			},
			ExpectedCertIndex: 0,
		},
		"matching SNI cert": {
			Cert: TestCertSpec{
				host: "localhost",
				ips:  []string{"127.0.0.1"},
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
					},
				},
			},
			ExpectedCertIndex: 0,
			ServerName:        "test.com",
		},
		"matching IP in SNI cert and the server cert": {
			// IPs must not be passed via SNI. Hence, the ServerName in the
			// HELLO packet is empty and the server should select the non-SNI cert.
			Cert: TestCertSpec{
				host: "localhost",
				ips:  []string{"10.0.0.1", "127.0.0.1"},
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "test.com",
						ips:  []string{"10.0.0.1"},
					},
				},
			},
			ExpectedCertIndex: -1,
			ServerName:        "10.0.0.1",
		},
		"wildcards": {
			Cert: TestCertSpec{
				host: "localhost",
				ips:  []string{"127.0.0.1"},
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host:  "test.com",
						names: []string{"*.test.com"},
					},
				},
			},
			ExpectedCertIndex: 0,
			ServerName:        "www.test.com",
		},

		"loopback: LoopbackClientServerNameOverride not on any cert": {
			Cert: TestCertSpec{
				host: "test.com",
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "localhost",
					},
				},
			},
			ExpectedCertIndex: 0,
		},
		"loopback: LoopbackClientServerNameOverride on server cert": {
			Cert: TestCertSpec{
				host: server.LoopbackClientServerNameOverride,
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: "localhost",
					},
				},
			},
			ExpectedCertIndex: 0,
		},
		"loopback: LoopbackClientServerNameOverride on SNI cert": {
			Cert: TestCertSpec{
				host: "localhost",
			},
			SNICerts: []NamedTestCertSpec{
				{
					TestCertSpec: TestCertSpec{
						host: server.LoopbackClientServerNameOverride,
					},
				},
			},
			ExpectedCertIndex: -1,
		},
		"loopback: bind to 0.0.0.0 => loopback uses localhost": {
			Cert: TestCertSpec{
				host: "localhost",
			},
			ExpectedCertIndex:                 -1,
			LoopbackClientBindAddressOverride: "0.0.0.0",
		},
	}

	specToName := func(spec TestCertSpec) string {
		name := spec.host + "_" + strings.Join(spec.names, ",") + "_" + strings.Join(spec.ips, ",")
		return strings.Replace(name, "*", "star", -1)
	}

NextTest:
	for title, test := range tests {
		// create server cert
		certDir := "testdata/" + specToName(test.Cert)
		serverCertBundleFile := filepath.Join(certDir, "cert")
		serverKeyFile := filepath.Join(certDir, "key")
		err := getOrCreateTestCertFiles(serverCertBundleFile, serverKeyFile, test.Cert)
		if err != nil {
			t.Errorf("%q - failed to create server cert: %v", title, err)
			continue NextTest
		}
		ca, err := caCertFromBundle(serverCertBundleFile)
		if err != nil {
			t.Errorf("%q - failed to extract ca cert from server cert bundle: %v", title, err)
			continue NextTest
		}
		caCerts := []*x509.Certificate{ca}

		// create SNI certs
		var namedCertKeys []utilflag.NamedCertKey
		serverSig, err := certFileSignature(serverCertBundleFile, serverKeyFile)
		if err != nil {
			t.Errorf("%q - failed to get server cert signature: %v", title, err)
			continue NextTest
		}
		signatures := map[string]int{
			serverSig: -1,
		}
		for j, c := range test.SNICerts {
			sniDir := filepath.Join(certDir, specToName(c.TestCertSpec))
			certBundleFile := filepath.Join(sniDir, "cert")
			keyFile := filepath.Join(sniDir, "key")
			err := getOrCreateTestCertFiles(certBundleFile, keyFile, c.TestCertSpec)
			if err != nil {
				t.Errorf("%q - failed to create SNI cert %d: %v", title, j, err)
				continue NextTest
			}

			namedCertKeys = append(namedCertKeys, utilflag.NamedCertKey{
				KeyFile:  keyFile,
				CertFile: certBundleFile,
				Names:    c.explicitNames,
			})

			ca, err := caCertFromBundle(certBundleFile)
			if err != nil {
				t.Errorf("%q - failed to extract ca cert from SNI cert %d: %v", title, j, err)
				continue NextTest
			}
			caCerts = append(caCerts, ca)

			// store index in namedCertKeys with the signature as the key
			sig, err := certFileSignature(certBundleFile, keyFile)
			if err != nil {
				t.Errorf("%q - failed get SNI cert %d signature: %v", title, j, err)
				continue NextTest
			}
			signatures[sig] = j
		}

		stopCh := make(chan struct{})
		func() {
			defer close(stopCh)

			// launch server
			config := setUp(t)

			v := fakeVersion()
			config.Version = &v

			config.EnableIndex = true
			secureOptions := &SecureServingOptions{
				BindAddress: net.ParseIP("127.0.0.1"),
				BindPort:    6443,
				ServerCert: GeneratableKeyCert{
					CertKey: CertKey{
						CertFile: serverCertBundleFile,
						KeyFile:  serverKeyFile,
					},
				},
				SNICertKeys: namedCertKeys,
			}
			config.LoopbackClientConfig = &restclient.Config{}
			if err := secureOptions.ApplyTo(&config); err != nil {
				t.Errorf("%q - failed applying the SecureServingOptions: %v", title, err)
				return
			}

			s, err := config.Complete().New("test", server.EmptyDelegate)
			if err != nil {
				t.Errorf("%q - failed creating the server: %v", title, err)
				return
			}

			// patch in a 0-port to enable auto port allocation
			s.SecureServingInfo.BindAddress = "127.0.0.1:0"

			// add poststart hook to know when the server is up.
			startedCh := make(chan struct{})
			s.AddPostStartHook("test-notifier", func(context PostStartHookContext) error {
				close(startedCh)
				return nil
			})
			preparedServer := s.PrepareRun()
			go func() {
				if err := preparedServer.Run(stopCh); err != nil {
					t.Fatal(err)
				}
			}()

			// load ca certificates into a pool
			roots := x509.NewCertPool()
			for _, caCert := range caCerts {
				roots.AddCert(caCert)
			}

			<-startedCh

			effectiveSecurePort := fmt.Sprintf("%d", preparedServer.EffectiveSecurePort())
			// try to dial
			addr := fmt.Sprintf("localhost:%s", effectiveSecurePort)
			t.Logf("Dialing %s as %q", addr, test.ServerName)
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				RootCAs:    roots,
				ServerName: test.ServerName, // used for SNI in the client HELLO packet
			})
			if err != nil {
				t.Errorf("%q - failed to connect: %v", title, err)
				return
			}

			// check returned server certificate
			sig := x509CertSignature(conn.ConnectionState().PeerCertificates[0])
			gotCertIndex, found := signatures[sig]
			if !found {
				t.Errorf("%q - unknown signature returned from server: %s", title, sig)
			}
			if gotCertIndex != test.ExpectedCertIndex {
				t.Errorf("%q - expected cert index %d, got cert index %d", title, test.ExpectedCertIndex, gotCertIndex)
			}

			conn.Close()

			// check that the loopback client can connect
			host := "127.0.0.1"
			if len(test.LoopbackClientBindAddressOverride) != 0 {
				host = test.LoopbackClientBindAddressOverride
			}
			s.LoopbackClientConfig.Host = net.JoinHostPort(host, effectiveSecurePort)
			if test.ExpectLoopbackClientError {
				if err == nil {
					t.Errorf("%q - expected error creating loopback client config", title)
				}
				return
			}
			if err != nil {
				t.Errorf("%q - failed creating loopback client config: %v", title, err)
				return
			}
			client, err := discovery.NewDiscoveryClientForConfig(s.LoopbackClientConfig)
			if err != nil {
				t.Errorf("%q - failed to create loopback client: %v", title, err)
				return
			}
			got, err := client.ServerVersion()
			if err != nil {
				t.Errorf("%q - failed to connect with loopback client: %v", title, err)
				return
			}
			if expected := &v; !reflect.DeepEqual(got, expected) {
				t.Errorf("%q - loopback client didn't get correct version info: expected=%v got=%v", title, expected, got)
			}
		}()
	}
}

func parseIPList(ips []string) []net.IP {
	var netIPs []net.IP
	for _, ip := range ips {
		netIPs = append(netIPs, net.ParseIP(ip))
	}
	return netIPs
}

func createTestTLSCerts(spec TestCertSpec) (tlsCert tls.Certificate, err error) {
	certPem, keyPem, err := generateSelfSignedCertKey(spec.host, parseIPList(spec.ips), spec.names)
	if err != nil {
		return tlsCert, err
	}

	tlsCert, err = tls.X509KeyPair(certPem, keyPem)
	return tlsCert, err
}

func getOrCreateTestCertFiles(certFileName, keyFileName string, spec TestCertSpec) (err error) {
	if _, err := os.Stat(certFileName); err == nil {
		if _, err := os.Stat(keyFileName); err == nil {
			return nil
		}
	}

	certPem, keyPem, err := generateSelfSignedCertKey(spec.host, parseIPList(spec.ips), spec.names)
	if err != nil {
		return err
	}

	os.MkdirAll(filepath.Dir(certFileName), os.FileMode(0755))
	err = ioutil.WriteFile(certFileName, certPem, os.FileMode(0755))
	if err != nil {
		return err
	}

	os.MkdirAll(filepath.Dir(keyFileName), os.FileMode(0755))
	err = ioutil.WriteFile(keyFileName, keyPem, os.FileMode(0755))
	if err != nil {
		return err
	}

	return nil
}

func caCertFromBundle(bundlePath string) (*x509.Certificate, error) {
	pemData, err := ioutil.ReadFile(bundlePath)
	if err != nil {
		return nil, err
	}

	// fetch last block
	var block *pem.Block
	for {
		var nextBlock *pem.Block
		nextBlock, pemData = pem.Decode(pemData)
		if nextBlock == nil {
			if block == nil {
				return nil, fmt.Errorf("no certificate found in %q", bundlePath)

			}
			return x509.ParseCertificate(block.Bytes)
		}
		block = nextBlock
	}
}

func x509CertSignature(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Signature)
}

func certFileSignature(certFile, keyFile string) (string, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", err
	}
	return certSignature(cert)
}

func certSignature(cert tls.Certificate) (string, error) {
	x509Certs, err := x509.ParseCertificates(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	return x509CertSignature(x509Certs[0]), nil
}

func fakeVersion() version.Info {
	return version.Info{
		Major:        "42",
		Minor:        "42",
		GitVersion:   "42",
		GitCommit:    "34973274ccef6ab4dfaaf86599792fa9c3fe4689",
		GitTreeState: "Dirty",
	}
}

// generateSelfSignedCertKey creates a self-signed certificate and key for the given host.
// Host may be an IP or a DNS name
// You may also specify additional subject alt names (either ip or dns names) for the certificate
func generateSelfSignedCertKey(host string, alternateIPs []net.IP, alternateDNS []string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s@%d", host, time.Now().Unix()),
		},
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 100),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	template.IPAddresses = append(template.IPAddresses, alternateIPs...)
	template.DNSNames = append(template.DNSNames, alternateDNS...)

	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Generate cert
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, err
	}

	// Generate key
	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, nil, err
	}

	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
}
