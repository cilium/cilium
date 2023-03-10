// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cilium/cilium/pkg/maps/ipcache"

	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {
	assert := assert.New(t)
	root := &Dir{
		base: base{
			Kind: "Dir",
			Name: "d0",
		},
		Tasks: []Task{
			&Exec{
				base: base{
					Kind: "Exec",
					Name: "e0",
				},
				Cmd:  "ls",
				Args: []string{"/etc/"},
			},
			&Exec{
				base: base{
					Kind: "Exec",
					Name: "e1",
				},
				Cmd:  "bpftool",
				Args: []string{"net", "show"},
			},
			&Dir{base: base{Kind: KindDir, Name: "z"}},
			&Request{base: base{Kind: KindRequest, Name: "z"}},
			NewPinnedBPFMap[ipcache.Key, ipcache.RemoteEndpointInfo]("cilium_ipcache"),
		},
	}
	d, err := json.MarshalIndent(root, "", "	")
	t.Log(string(d))
	assert.NoError(err)
	rootTask, err := Decode(bytes.NewReader(d))
	assert.NoError(err)
	assert.EqualValues(root, rootTask)
}
