// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build boringcrypto

package main

// Package fipsonly restricts all TLS configuration to FIPS-approved settings.
// See https://github.com/golang/go/blob/master/src/crypto/tls/fipsonly/fipsonly.go
import _ "crypto/tls/fipsonly"
