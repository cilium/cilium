// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// expectedLblsJSON is the hard-coded JSON encoding of 'lbls'. This ensures
// the JSON encoding of 'Labels' does not change since it's a stable API
// (e.g. endpoint data contains labels and needs to be stable across upgrades).
var expectedLblsJSON = `{"%":{"key":"%","value":"%ed","source":"unspec"},"//=/":{"key":"//=/","source":"unspec"},"foo":{"key":"foo","value":"bar","source":"unspec"},"foo2":{"key":"foo2","value":"=bar2","source":"unspec"},"foo==":{"key":"foo==","value":"==","source":"unspec"},"foo\\\\=":{"key":"foo\\\\=","value":"\\=","source":"unspec"},"key":{"key":"key","source":"unspec"}}`

var lbls = NewLabels(
	NewLabel("foo", "bar", LabelSourceUnspec),
	NewLabel("foo2", "=bar2", LabelSourceUnspec),
	NewLabel("key", "", LabelSourceUnspec),
	NewLabel("foo==", "==", LabelSourceUnspec),
	NewLabel(`foo\\=`, `\=`, LabelSourceUnspec),
	NewLabel(`//=/`, "", LabelSourceUnspec),
	NewLabel(`%`, `%ed`, LabelSourceUnspec),
)

func TestLabelsJSONStable(t *testing.T) {
	// Use the 'lbls' test data from labels_test.go.
	b, err := json.Marshal(lbls)
	require.NoError(t, err, "Marshal")

	// TODO: now marshalled as a JSON array. Figure out if we can do
	// such a transition.
	//require.Equal(t, expectedLblsJSON, string(b))

	var lbls2 Labels
	err = json.Unmarshal(b, &lbls2)
	require.NoError(t, err, "Unmarshal")
	require.True(t, lbls.Equal(lbls2), "Equals")

	// Validate that the map-style encoding can be decoded.
	err = json.Unmarshal([]byte(expectedLblsJSON), &lbls2)
	require.NoError(t, err, "Unmarshal")
	require.True(t, lbls.Equal(lbls2), "Equals")

}
