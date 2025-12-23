// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGL4CTranslator_Translate(t *testing.T) {
	t.Run("empty model", func(t *testing.T) {
		translator := NewGL4CTranslator()
		result, err := translator.Translate("default", "test", nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}
