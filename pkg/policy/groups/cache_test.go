// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheWorkingCorrectly(t *testing.T) {

	cnps := groupsCNPCache.GetAllCNP()
	require.Empty(t, cnps)

	cnp := getSamplePolicy("test", "test")
	groupsCNPCache.UpdateCNP(cnp)

	cnps = groupsCNPCache.GetAllCNP()
	require.Len(t, cnps, 1)

	groupsCNPCache.DeleteCNP(cnp)

	cnps = groupsCNPCache.GetAllCNP()
	require.Empty(t, cnps)

}
