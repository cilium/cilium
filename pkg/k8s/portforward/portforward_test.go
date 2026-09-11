// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package portforward

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

func TestCreateDialer(t *testing.T) {
	config := &rest.Config{Host: "https://localhost:6443"}
	u, err := url.Parse("https://localhost:6443/api/v1/namespaces/default/pods/foo/portforward")
	require.NoError(t, err)

	dialer, err := createDialer(config, u)
	require.NoError(t, err)
	require.NotNil(t, dialer)
}
