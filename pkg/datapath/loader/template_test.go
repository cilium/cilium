// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestWrap(t *testing.T) {
	var (
		realEPBuffer   bytes.Buffer
		templateBuffer bytes.Buffer
	)

	realEP := testutils.NewTestEndpoint(t)
	template := wrap(&realEP)
	cfg := configWriterForTest(t)

	// Write the configuration that should be the same, and verify it is.
	err := cfg.WriteTemplateConfig(&realEPBuffer, &localNodeConfig, &realEP)
	require.NoError(t, err)
	err = cfg.WriteTemplateConfig(&templateBuffer, &localNodeConfig, template)
	require.NoError(t, err)
	require.Equal(t, realEPBuffer.String(), templateBuffer.String())
}
