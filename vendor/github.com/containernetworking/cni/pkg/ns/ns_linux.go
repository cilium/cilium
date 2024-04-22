// Copyright 2022 CNI authors
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

package ns

import (
	"runtime"

	"github.com/vishvananda/netns"

	"github.com/containernetworking/cni/pkg/types"
)

// Returns an object representing the current OS thread's network namespace
func getCurrentNS() (netns.NsHandle, error) {
	// Lock the thread in case other goroutine executes in it and changes its
	// network namespace after getCurrentThreadNetNSPath(), otherwise it might
	// return an unexpected network namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return netns.Get()
}

func CheckNetNS(nsPath string) (bool, *types.Error) {
	ns, err := netns.GetFromPath(nsPath)
	// Let plugins check whether nsPath from args is valid. Also support CNI DEL for empty nsPath as already-deleted nsPath.
	if err != nil {
		return false, nil
	}
	defer ns.Close()

	pluginNS, err := getCurrentNS()
	if err != nil {
		return false, types.NewError(types.ErrInvalidNetNS, "get plugin's netns failed", "")
	}
	defer pluginNS.Close()

	return pluginNS.Equal(ns), nil
}
