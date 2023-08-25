package tlsconfig

import (
	"crypto/tls"
)

// GetCertificateInfo is an empty placeholder for future expansion
type GetCertificateInfo struct {
}

// GotCertificateInfo provides err and TLS certificate info to Trace
type GotCertificateInfo struct {
	Cert *tls.Certificate
	Err  error
}

// Trace is the interface to define what functions are triggered when functions
// in tlsconfig are called
type Trace struct {
	GetCertificate func(GetCertificateInfo) interface{}
	GotCertificate func(GotCertificateInfo, interface{})
}
