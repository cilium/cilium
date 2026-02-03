// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

var DefaultConfig = Config{
	EnableZTunnel: false,
}

type Config struct {
	EnableZTunnel bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
}

// SpiffeIDPathFunc returns the SPIFFE ID path in the form of /ns/{namespace}/sa/{serviceaccount}
func SpiffeIDPathFunc(namespacedname string) string {
	parts := strings.Split(namespacedname, "/")
	if len(parts) != 2 {
		return ""
	}
	return fmt.Sprintf("/ns/%s/sa/%s", parts[0], parts[1])
}

// SpiffeIDSelectorsFunc returns the SPIFFE ID selectors for a given service account's namespaced name.
// The selectors are in the form of:
//
//	{Type: "k8s", Value: "ns:<namespace>"}
//	{Type: "k8s", Value: "sa:<serviceaccount>"}
func SpiffeIDSelectorsFunc(namespacedname string) []*types.Selector {
	parts := strings.Split(namespacedname, "/")
	if len(parts) != 2 {
		return nil
	}
	return []*types.Selector{
		{
			Type:  "k8s",
			Value: "ns:" + parts[0],
		},
		{
			Type:  "k8s",
			Value: "sa:" + parts[1],
		},
	}
}
