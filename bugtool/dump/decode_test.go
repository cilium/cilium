// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeAndDecode(t *testing.T) {
	assert := assert.New(t)
	root := NewDir(
		"d0",
		[]Task{
			NewExec("e0", "json", "ls", "/var"),
			NewExec("e1", "json", "ls", "/tmp"),
			NewDir("d1", Tasks{NewExec("c2", "txt", "ls", "/")}),
			NewRequest("r0", "https://admin/0"),
			NewRequest("r1", "https://admin/1").WithUnixSocket("/run/cilium/cilium.sock"),
			NewRequest("r2", "https://admin/2").WithUnixSocketExists("/run/cilium/cilium.sock"),
			NewFile("/tmp/foo"),
		},
	)
	d, err := json.MarshalIndent(root, "", "	")
	assert.NoError(err)
	rootTask, err := Decode(bytes.NewReader(d))
	assert.NoError(err)
	assert.EqualValues(root, rootTask)
}
