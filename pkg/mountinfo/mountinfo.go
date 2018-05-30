// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mountinfo

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/common/files"
)

const (
	FilesystemTypeBPFFS = "bpf"
)

// MountInfo is a struct representing information from /proc/pid/mountinfo. More
// information about file syntax:
// https://www.kernel.org/doc/Documentation/filesystems/proc.txt
type MountInfo struct {
	MountID        int64
	ParentID       int64
	StDev          string
	Root           string
	MountPoint     string
	MountOptions   string
	OptionalFields string
	Separator      string
	FilesystemType string
	MountSource    string
	SuperOptions   string
}

func GetMountInfo() ([]*MountInfo, error) {
	var result []*MountInfo

	scanner, err := files.NewFileScanner("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer scanner.Close()

	for scanner.Scan() {
		mountInfoRaw := scanner.Text()
		mountInfoSlc := strings.Split(scanner.Text(), " ")
		if len(mountInfoSlc) != 11 {
			return nil, fmt.Errorf("invalid mountinfo entry: %s", mountInfoRaw)
		}

		mountID, err := strconv.ParseInt(mountInfoSlc[0], 10, 64)
		if err != nil {
			return nil, err
		}

		parentID, err := strconv.ParseInt(mountInfoSlc[1], 10, 64)
		if err != nil {
			return nil, err
		}

		result = append(result, &MountInfo{
			MountID:        mountID,
			ParentID:       parentID,
			StDev:          mountInfoSlc[2],
			Root:           mountInfoSlc[3],
			MountPoint:     mountInfoSlc[4],
			MountOptions:   mountInfoSlc[5],
			OptionalFields: mountInfoSlc[6],
			Separator:      mountInfoSlc[7],
			FilesystemType: mountInfoSlc[8],
			MountSource:    mountInfoSlc[9],
			SuperOptions:   mountInfoSlc[10],
		})
	}

	return result, nil
}
