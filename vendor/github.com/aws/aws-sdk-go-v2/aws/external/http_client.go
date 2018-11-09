package external

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws/awserr"
)

func addHTTPClientCABundle(client *http.Client, pemCerts []byte) error {
	var t *http.Transport

	switch v := client.Transport.(type) {
	case *http.Transport:
		t = v
	default:
		if client.Transport != nil {
			return awserr.New("LoadCustomCABundleError",
				"unable to set custom CA bundle trasnsport must be http.Transport type", nil)
		}
	}

	if t == nil {
		t = &http.Transport{}
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	if t.TLSClientConfig.RootCAs == nil {
		t.TLSClientConfig.RootCAs = x509.NewCertPool()
	}

	if !t.TLSClientConfig.RootCAs.AppendCertsFromPEM(pemCerts) {
		return awserr.New("LoadCustomCABundleError",
			"failed to load custom CA bundle PEM file", nil)
	}

	client.Transport = t

	return nil
}
