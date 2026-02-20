// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// FileInfo tracks flow file information.
type FileInfo struct {
	Name string `json:"name,omitempty"`
	Line uint32 `json:"line,omitempty"`
}

func (f FileInfo) isEmpty() bool {
	return f.Name == "" && f.Line == 0
}

func (f FileInfo) toProto() *flow.FileInfo {
	if f.isEmpty() {
		return nil
	}

	return &flow.FileInfo{
		Name: f.Name,
		Line: f.Line,
	}
}

func protoToFileInfo(f *flow.FileInfo) FileInfo {
	if f == nil {
		return FileInfo{}
	}

	return FileInfo{
		Name: f.Name,
		Line: f.Line,
	}
}
