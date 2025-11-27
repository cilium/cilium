// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDriverType(t *testing.T) {
	t.Run("test (un)marshaling", func(t *testing.T) {
		for i := range DeviceManagerTypeUnknown {
			// make sure we handle all supported types
			str, err := i.MarshalText()
			require.NoError(t, err)
			require.NotNil(t, str)

			var unmarshaled DeviceManagerType
			require.NoError(t, unmarshaled.UnmarshalText(str))
			require.Equal(t, i, unmarshaled)

			require.NotEmpty(t, i.String())
		}

		dontExist := DeviceManagerTypeUnknown + 1
		str, err := dontExist.MarshalText()
		require.Error(t, err)
		require.Nil(t, str)

		jsonText := `\"idontexist\"`
		require.Error(t, dontExist.UnmarshalText([]byte(jsonText)))
		require.NotZero(t, dontExist)

		require.Empty(t, dontExist.String())
	})
}
