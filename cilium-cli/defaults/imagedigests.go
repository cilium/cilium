// SPDX-License-Identifier: Apache-2.0
// Copyright 2021-2022 Authors of Cilium

package defaults

import (
	_ "embed"
	"encoding/json"
)

//go:embed imagedigests.json
var imageDigestsJSON []byte

// WellKnownImageDigests maps well known image paths and tags to their digests.
var WellKnownImageDigests = make(map[string]string)

func init() {
	pathTagDigests := make(map[string]map[string]string)
	if err := json.Unmarshal(imageDigestsJSON, &pathTagDigests); err != nil {
		panic(err)
	}
	for path, tagDigests := range pathTagDigests {
		for tag, digest := range tagDigests {
			WellKnownImageDigests[path+":"+tag] = digest
		}
	}
}
