// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package validate

import (
	"errors"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/pkg/defaults"
)

var (
	// ErrInvalidKeypair means that a TLS keypair is required but only one of the
	// key or certificate was provided.
	ErrInvalidKeypair = errors.New("certificate and private key are both required, but only one was provided")

	// ErrTLSRequired means that Transport Layer Security (TLS) is required but
	// not set.
	ErrTLSRequired = errors.New("transport layer security required")
)

func init() {
	FlagFuncs = append(FlagFuncs, validateMutualTLSFlags)
}

// validateMutualTLSFlags validates that TLS is set if a client keypair is
// provided.
func validateMutualTLSFlags(_ *cobra.Command, vp *viper.Viper) error {
	var needTLS bool
	switch {
	case vp.GetString(config.KeyTLSClientKeyFile) != "" && vp.GetString(config.KeyTLSClientCertFile) != "":
		needTLS = true
	case vp.GetString(config.KeyTLSClientKeyFile) != "":
		fallthrough
	case vp.GetString(config.KeyTLSClientCertFile) != "":
		return ErrInvalidKeypair
	}

	if needTLS && !(vp.GetBool(config.KeyTLS) || strings.HasPrefix(vp.GetString(config.KeyServer), defaults.TargetTLSPrefix)) {
		return ErrTLSRequired
	}
	return nil
}
