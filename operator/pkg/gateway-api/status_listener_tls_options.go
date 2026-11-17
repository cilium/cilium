// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"cmp"
	"fmt"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

// Versions lower than 1.2 are excluded due to insufficient security.
var validTLSVersions = map[string]int{
	"1.2": 2,
	"1.3": 3,
}

// Valid cipher suites were retrieved from BoringSSL version used by Cilium Envoy.
// Ref: https://github.com/google/boringssl/blob/0.20260929.0/ssl/ssl_cipher.cc
//
// All commented cipher suites stay for visibility.
var validTLSCipherSuites = map[string]struct{}{
	"AES128-GCM-SHA256":             {},
	"AES128-SHA":                    {},
	"AES256-GCM-SHA384":             {},
	"AES256-SHA":                    {},
	"ECDHE-ECDSA-AES128-GCM-SHA256": {},
	"ECDHE-ECDSA-AES128-SHA":        {},
	"ECDHE-ECDSA-AES256-GCM-SHA384": {},
	"ECDHE-ECDSA-AES256-SHA":        {},
	"ECDHE-ECDSA-CHACHA20-POLY1305": {},
	"ECDHE-RSA-AES128-GCM-SHA256":   {},
	"ECDHE-RSA-AES128-SHA":          {},
	"ECDHE-RSA-AES256-GCM-SHA384":   {},
	"ECDHE-RSA-AES256-SHA":          {},
	"ECDHE-RSA-CHACHA20-POLY1305":   {},
	// The following cipher suites are marked as deprecated.
	// However, they still can be valid.
	"DES-CBC3-SHA":              {},
	"ECDHE-ECDSA-AES128-SHA256": {},
	"ECDHE-RSA-AES128-SHA256":   {},
	// The following cipher suites required PSK,
	// which is not relevant for this use case.
	// "ECDHE-PSK-AES128-CBC-SHA":    {},
	// "ECDHE-PSK-AES256-CBC-SHA":    {},
	// "ECDHE-PSK-CHACHA20-POLY1305": {},
	// "PSK-AES128-CBC-SHA":          {},
	// "PSK-AES256-CBC-SHA":          {},
	// The following cipher suites are valid for TLS 1.3 only
	// and cannot be configured via `cipher_suites` field.
	// "TLS_AES_128_GCM_SHA256":       {},
	// "TLS_AES_256_GCM_SHA384":       {},
	// "TLS_CHACHA20_POLY1305_SHA256": {},
}

// Valid ECDH curves were retrieved from BoringSSL version used by Cilium Envoy.
// Ref: https://github.com/google/boringssl/blob/0.20260929.0/ssl/ssl_key_share.cc
var validTLSECDHCurves = map[string]struct{}{
	"MLKEM1024":      {},
	"P-256":          {},
	"P-384":          {},
	"P-521":          {},
	"X25519":         {},
	"X25519MLKEM768": {},
}

// Valid signature algorithms were retrieved from BoringSSL version used by Cilium Envoy.
// Ref: https://github.com/google/boringssl/blob/0.20260929.0/ssl/ssl_privkey.cc
//
// All commented signature algorithms stay for visibility.
var validTLSSignatureAlgorithms = map[string]struct{}{
	"ecdsa_secp256r1_sha256": {},
	"ecdsa_secp384r1_sha384": {},
	"ecdsa_secp521r1_sha512": {},
	"ecdsa_sha1":             {},
	"ed25519":                {},
	"rsa_pkcs1_sha1":         {},
	"rsa_pkcs1_sha256":       {},
	"rsa_pkcs1_sha384":       {},
	"rsa_pkcs1_sha512":       {},
	"rsa_pss_rsae_sha256":    {},
	"rsa_pss_rsae_sha384":    {},
	"rsa_pss_rsae_sha512":    {},
	// The following signature algorithms are only valid for TLS 1.3.
	"mldsa44": {},
	"mldsa65": {},
	"mldsa87": {},
	// The following signature algorithm is only valid for TLS 1.3 client-certificate signatures.
	"rsa_pkcs1_sha256_legacy": {},
	// The following signature algorithm is a BoringSSL internal one for TLS 1.0/1.1.
	// "rsa_pkcs1_md5_sha1": {},
}

func parseTLSOptionValues(option, value string, supportedValues map[string]struct{}) ([]string, error) {
	values := strings.Split(value, ",")
	seen := make(map[string]struct{})
	for i, v := range values {
		v = strings.TrimSpace(v)
		values[i] = v
		if _, ok := seen[v]; ok {
			return nil, fmt.Errorf("TLS Value %s duplicates in %s", v, option)
		}
		if _, ok := supportedValues[v]; !ok {
			return nil, fmt.Errorf("TLS Value %s is not supported in %s", v, option)
		}
		seen[v] = struct{}{}
	}
	return values, nil
}

func parseTLSOptions(l gatewayv1.Listener) (*model.TLSOptions, error) {
	if l.TLS == nil {
		return nil, nil
	}

	passthroughListener := helpers.IsTLSPassthroughListener(&l)

	parsed := &model.TLSOptions{}
	for o, v := range l.TLS.Options {
		option := string(o)
		value := string(v)
		// Validate only 'cilium.io/' options, other should be ignored.
		if !strings.HasPrefix(option, "cilium.io/") {
			continue
		}

		if passthroughListener {
			return nil, fmt.Errorf("TLS option %s is not supported on TLS passthrough listeners", option)
		}

		switch option {
		case model.TLSOptionsMinVersion:
			if _, ok := validTLSVersions[value]; !ok {
				return nil, fmt.Errorf("TLS Value %s is not supported in %s", value, option)
			}
			parsed.MinVersion = value
		case model.TLSOptionsMaxVersion:
			if _, ok := validTLSVersions[value]; !ok {
				return nil, fmt.Errorf("TLS Value %s is not supported in %s", value, option)
			}
			parsed.MaxVersion = value
		case model.TLSOptionsCipherSuites:
			values, err := parseTLSOptionValues(option, value, validTLSCipherSuites)
			if err != nil {
				return nil, err
			}
			parsed.CipherSuites = values
		case model.TLSOptionsECDHCurves:
			values, err := parseTLSOptionValues(option, value, validTLSECDHCurves)
			if err != nil {
				return nil, err
			}
			parsed.ECDHCurves = values
		case model.TLSOptionsSignatureAlgorithms:
			values, err := parseTLSOptionValues(option, value, validTLSSignatureAlgorithms)
			if err != nil {
				return nil, err
			}
			parsed.SignatureAlgorithms = values
		default:
			return nil, fmt.Errorf("TLS Option %s is not supported", option)
		}
	}

	min := cmp.Or(parsed.MinVersion, model.TLSOptionsDefaultMinVersion)
	max := cmp.Or(parsed.MaxVersion, model.TLSOptionsDefaultMaxVersion)
	if validTLSVersions[min] > validTLSVersions[max] {
		return nil, fmt.Errorf("TLS minimum version %s must not exceed maximum version %s", min, max)
	}

	if parsed.MinVersion == "" &&
		parsed.MaxVersion == "" &&
		len(parsed.CipherSuites) == 0 &&
		len(parsed.ECDHCurves) == 0 &&
		len(parsed.SignatureAlgorithms) == 0 {
		return nil, nil
	}

	return parsed, nil
}
