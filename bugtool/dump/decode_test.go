// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {
	assert := assert.New(t)
	root := &Dir{
		Base: Base{
			Kind: "Dir",
			Name: "d0",
		},
		Tasks: []Task{
			&Exec{
				Base: Base{
					Kind: "Exec",
					Name: "e0",
				},
				Cmd:  "ls",
				Args: []string{"/etc/"},
			},
			&Exec{
				Base: Base{
					Kind: "Exec",
					Name: "e1",
				},
				Cmd:  "bpftool",
				Args: []string{"net", "show"},
			},
			&Dir{Base: Base{Kind: KindDir, Name: "z"}},
			&Request{Base: Base{Kind: KindRequest, Name: "z"}},
		},
	}
	d, err := json.MarshalIndent(root, "", "	")
	assert.NoError(err)
	rootTask, err := Decode(bytes.NewReader(d))
	assert.NoError(err)
	assert.EqualValues(root, rootTask)
}
