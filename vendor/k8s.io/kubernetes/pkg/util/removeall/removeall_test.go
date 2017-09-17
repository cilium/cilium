/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package removeall

import (
	"errors"
	"os"
	"path"
	"strings"
	"testing"

	utiltesting "k8s.io/client-go/util/testing"
	"k8s.io/kubernetes/pkg/util/mount"
)

type fakeMounter struct{}

var _ mount.Interface = &fakeMounter{}

func (mounter *fakeMounter) Mount(source string, target string, fstype string, options []string) error {
	return errors.New("not implemented")
}
func (mounter *fakeMounter) Unmount(target string) error {
	return errors.New("not implemented")
}
func (mounter *fakeMounter) List() ([]mount.MountPoint, error) {
	return nil, errors.New("not implemented")
}
func (mounter fakeMounter) DeviceOpened(pathname string) (bool, error) {
	return false, errors.New("not implemented")
}
func (mounter *fakeMounter) PathIsDevice(pathname string) (bool, error) {
	return false, errors.New("not implemented")
}
func (mounter *fakeMounter) GetDeviceNameFromMount(mountPath, pluginDir string) (string, error) {
	return "", errors.New("not implemented")
}
func (mounter *fakeMounter) IsMountPointMatch(mp mount.MountPoint, dir string) bool {
	return (mp.Path == dir)
}
func (mounter *fakeMounter) IsNotMountPoint(dir string) (bool, error) {
	return mount.IsNotMountPoint(mounter, dir)
}
func (mounter *fakeMounter) IsLikelyNotMountPoint(file string) (bool, error) {
	name := path.Base(file)
	if strings.HasPrefix(name, "mount") {
		return false, nil
	}
	if strings.HasPrefix(name, "err") {
		return false, errors.New("mock error")
	}
	return true, nil
}

func (mounter *fakeMounter) MakeRShared(path string) error {
	return nil
}

func TestRemoveAllOneFilesystem(t *testing.T) {
	tests := []struct {
		name string
		// Items of the test directory. Directories end with "/".
		// Directories starting with "mount" are considered to be mount points.
		// Directories starting with "err" will cause an error in
		// IsLikelyNotMountPoint.
		items       []string
		expectError bool
	}{
		{
			"empty dir",
			[]string{},
			false,
		},
		{
			"non-mount",
			[]string{
				"dir/",
				"dir/file",
				"dir2/",
				"file2",
			},
			false,
		},
		{
			"mount",
			[]string{
				"dir/",
				"dir/file",
				"dir2/",
				"file2",
				"mount/",
				"mount/file3",
			},
			true,
		},
		{
			"innermount",
			[]string{
				"dir/",
				"dir/file",
				"dir/dir2/",
				"dir/dir2/file2",
				"dir/dir2/mount/",
				"dir/dir2/mount/file3",
			},
			true,
		},
		{
			"error",
			[]string{
				"dir/",
				"dir/file",
				"dir2/",
				"file2",
				"err/",
				"err/file3",
			},
			true,
		},
	}

	for _, test := range tests {
		tmpDir, err := utiltesting.MkTmpdir("removeall-" + test.name + "-")
		if err != nil {
			t.Fatalf("Can't make a tmp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		// Create the directory structure
		for _, item := range test.items {
			if strings.HasSuffix(item, "/") {
				item = strings.TrimRight(item, "/")
				if err = os.Mkdir(path.Join(tmpDir, item), 0777); err != nil {
					t.Fatalf("error creating %s: %v", item, err)
				}
			} else {
				f, err := os.Create(path.Join(tmpDir, item))
				if err != nil {
					t.Fatalf("error creating %s: %v", item, err)
				}
				f.Close()
			}
		}

		mounter := &fakeMounter{}
		err = RemoveAllOneFilesystem(mounter, tmpDir)
		if err == nil && test.expectError {
			t.Errorf("test %q failed: expected error and got none", test.name)
		}
		if err != nil && !test.expectError {
			t.Errorf("test %q failed: unexpected error: %v", test.name, err)
		}
	}
}
