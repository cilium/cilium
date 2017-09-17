// +build linux

/*
Copyright 2014 The Kubernetes Authors.

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

package host_path

import (
	"fmt"
	"os"
	"testing"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes/fake"
	utilfile "k8s.io/kubernetes/pkg/util/file"
	"k8s.io/kubernetes/pkg/volume"
	volumetest "k8s.io/kubernetes/pkg/volume/testing"
)

func newHostPathType(pathType string) *v1.HostPathType {
	hostPathType := new(v1.HostPathType)
	*hostPathType = v1.HostPathType(pathType)
	return hostPathType
}

func newHostPathTypeList(pathType ...string) []*v1.HostPathType {
	typeList := []*v1.HostPathType{}
	for _, ele := range pathType {
		typeList = append(typeList, newHostPathType(ele))
	}

	return typeList
}

func TestCanSupport(t *testing.T) {
	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("fake", nil, nil))

	plug, err := plugMgr.FindPluginByName("kubernetes.io/host-path")
	if err != nil {
		t.Errorf("Can't find the plugin by name")
	}
	if plug.GetPluginName() != "kubernetes.io/host-path" {
		t.Errorf("Wrong name: %s", plug.GetPluginName())
	}
	if !plug.CanSupport(&volume.Spec{Volume: &v1.Volume{VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{}}}}) {
		t.Errorf("Expected true")
	}
	if !plug.CanSupport(&volume.Spec{PersistentVolume: &v1.PersistentVolume{Spec: v1.PersistentVolumeSpec{PersistentVolumeSource: v1.PersistentVolumeSource{HostPath: &v1.HostPathVolumeSource{}}}}}) {
		t.Errorf("Expected true")
	}
	if plug.CanSupport(&volume.Spec{Volume: &v1.Volume{VolumeSource: v1.VolumeSource{}}}) {
		t.Errorf("Expected false")
	}
}

func TestGetAccessModes(t *testing.T) {
	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("/tmp/fake", nil, nil))

	plug, err := plugMgr.FindPersistentPluginByName("kubernetes.io/host-path")
	if err != nil {
		t.Errorf("Can't find the plugin by name")
	}
	if len(plug.GetAccessModes()) != 1 || plug.GetAccessModes()[0] != v1.ReadWriteOnce {
		t.Errorf("Expected %s PersistentVolumeAccessMode", v1.ReadWriteOnce)
	}
}

func TestRecycler(t *testing.T) {
	plugMgr := volume.VolumePluginMgr{}
	pluginHost := volumetest.NewFakeVolumeHost("/tmp/fake", nil, nil)
	plugMgr.InitPlugins([]volume.VolumePlugin{&hostPathPlugin{nil, volume.VolumeConfig{}}}, nil, pluginHost)

	spec := &volume.Spec{PersistentVolume: &v1.PersistentVolume{Spec: v1.PersistentVolumeSpec{PersistentVolumeSource: v1.PersistentVolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/foo"}}}}}
	_, err := plugMgr.FindRecyclablePluginBySpec(spec)
	if err != nil {
		t.Errorf("Can't find the plugin by name")
	}
}

func TestDeleter(t *testing.T) {
	// Deleter has a hard-coded regex for "/tmp".
	tempPath := fmt.Sprintf("/tmp/hostpath/%s", uuid.NewUUID())
	defer os.RemoveAll(tempPath)
	err := os.MkdirAll(tempPath, 0750)
	if err != nil {
		t.Fatalf("Failed to create tmp directory for deleter: %v", err)
	}

	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("/tmp/fake", nil, nil))

	spec := &volume.Spec{PersistentVolume: &v1.PersistentVolume{Spec: v1.PersistentVolumeSpec{PersistentVolumeSource: v1.PersistentVolumeSource{HostPath: &v1.HostPathVolumeSource{Path: tempPath}}}}}
	plug, err := plugMgr.FindDeletablePluginBySpec(spec)
	if err != nil {
		t.Errorf("Can't find the plugin by name")
	}
	deleter, err := plug.NewDeleter(spec)
	if err != nil {
		t.Errorf("Failed to make a new Deleter: %v", err)
	}
	if deleter.GetPath() != tempPath {
		t.Errorf("Expected %s but got %s", tempPath, deleter.GetPath())
	}
	if err := deleter.Delete(); err != nil {
		t.Errorf("Mock Recycler expected to return nil but got %s", err)
	}
	if exists, _ := utilfile.FileExists(tempPath); exists {
		t.Errorf("Temp path expected to be deleted, but was found at %s", tempPath)
	}
}

func TestDeleterTempDir(t *testing.T) {
	tests := map[string]struct {
		expectedFailure bool
		path            string
	}{
		"just-tmp": {true, "/tmp"},
		"not-tmp":  {true, "/nottmp"},
		"good-tmp": {false, "/tmp/scratch"},
	}

	for name, test := range tests {
		plugMgr := volume.VolumePluginMgr{}
		plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("/tmp/fake", nil, nil))
		spec := &volume.Spec{PersistentVolume: &v1.PersistentVolume{Spec: v1.PersistentVolumeSpec{PersistentVolumeSource: v1.PersistentVolumeSource{HostPath: &v1.HostPathVolumeSource{Path: test.path}}}}}
		plug, _ := plugMgr.FindDeletablePluginBySpec(spec)
		deleter, _ := plug.NewDeleter(spec)
		err := deleter.Delete()
		if err == nil && test.expectedFailure {
			t.Errorf("Expected failure for test '%s' but got nil err", name)
		}
		if err != nil && !test.expectedFailure {
			t.Errorf("Unexpected failure for test '%s': %v", name, err)
		}
	}
}

func TestProvisioner(t *testing.T) {
	tempPath := fmt.Sprintf("/tmp/hostpath/%s", uuid.NewUUID())
	defer os.RemoveAll(tempPath)
	err := os.MkdirAll(tempPath, 0750)

	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{ProvisioningEnabled: true}),
		nil,
		volumetest.NewFakeVolumeHost("/tmp/fake", nil, nil))
	spec := &volume.Spec{PersistentVolume: &v1.PersistentVolume{Spec: v1.PersistentVolumeSpec{PersistentVolumeSource: v1.PersistentVolumeSource{HostPath: &v1.HostPathVolumeSource{Path: tempPath}}}}}
	plug, err := plugMgr.FindCreatablePluginBySpec(spec)
	if err != nil {
		t.Errorf("Can't find the plugin by name")
	}
	options := volume.VolumeOptions{
		PVC: volumetest.CreateTestPVC("1Gi", []v1.PersistentVolumeAccessMode{v1.ReadWriteOnce}),
		PersistentVolumeReclaimPolicy: v1.PersistentVolumeReclaimDelete,
	}
	creater, err := plug.NewProvisioner(options)
	if err != nil {
		t.Errorf("Failed to make a new Provisioner: %v", err)
	}
	pv, err := creater.Provision()
	if err != nil {
		t.Errorf("Unexpected error creating volume: %v", err)
	}
	if pv.Spec.HostPath.Path == "" {
		t.Errorf("Expected pv.Spec.HostPath.Path to not be empty: %#v", pv)
	}
	expectedCapacity := resource.NewQuantity(1*1024*1024*1024, resource.BinarySI)
	actualCapacity := pv.Spec.Capacity[v1.ResourceStorage]
	expectedAmt := expectedCapacity.Value()
	actualAmt := actualCapacity.Value()
	if expectedAmt != actualAmt {
		t.Errorf("Expected capacity %+v but got %+v", expectedAmt, actualAmt)
	}

	if pv.Spec.PersistentVolumeReclaimPolicy != v1.PersistentVolumeReclaimDelete {
		t.Errorf("Expected reclaim policy %+v but got %+v", v1.PersistentVolumeReclaimDelete, pv.Spec.PersistentVolumeReclaimPolicy)
	}

	os.RemoveAll(pv.Spec.HostPath.Path)
}

func TestInvalidHostPath(t *testing.T) {
	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("fake", nil, nil))

	plug, err := plugMgr.FindPluginByName(hostPathPluginName)
	if err != nil {
		t.Fatalf("Unable to find plugin %s by name: %v", hostPathPluginName, err)
	}
	spec := &v1.Volume{
		Name:         "vol1",
		VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/no/backsteps/allowed/.."}},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("poduid")}}
	mounter, err := plug.NewMounter(volume.NewSpecFromVolume(spec), pod, volume.VolumeOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = mounter.SetUp(nil)
	expectedMsg := "invalid HostPath `/no/backsteps/allowed/..`: must not contain '..'"
	if err.Error() != expectedMsg {
		t.Fatalf("expected error `%s` but got `%s`", expectedMsg, err)
	}
}

func TestPlugin(t *testing.T) {
	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("fake", nil, nil))

	plug, err := plugMgr.FindPluginByName("kubernetes.io/host-path")
	if err != nil {
		t.Errorf("Can't find the plugin by name")
	}

	volPath := "/tmp/vol1"
	spec := &v1.Volume{
		Name:         "vol1",
		VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: volPath, Type: newHostPathType(string(v1.HostPathDirectoryOrCreate))}},
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("poduid")}}
	defer os.RemoveAll(volPath)
	mounter, err := plug.NewMounter(volume.NewSpecFromVolume(spec), pod, volume.VolumeOptions{})
	if err != nil {
		t.Errorf("Failed to make a new Mounter: %v", err)
	}
	if mounter == nil {
		t.Fatalf("Got a nil Mounter")
	}

	path := mounter.GetPath()
	if path != volPath {
		t.Errorf("Got unexpected path: %s", path)
	}

	if err := mounter.SetUp(nil); err != nil {
		t.Errorf("Expected success, got: %v", err)
	}

	unmounter, err := plug.NewUnmounter("vol1", types.UID("poduid"))
	if err != nil {
		t.Errorf("Failed to make a new Unmounter: %v", err)
	}
	if unmounter == nil {
		t.Fatalf("Got a nil Unmounter")
	}

	if err := unmounter.TearDown(); err != nil {
		t.Errorf("Expected success, got: %v", err)
	}
}

func TestPersistentClaimReadOnlyFlag(t *testing.T) {
	pv := &v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pvA",
		},
		Spec: v1.PersistentVolumeSpec{
			PersistentVolumeSource: v1.PersistentVolumeSource{
				HostPath: &v1.HostPathVolumeSource{Path: "foo", Type: newHostPathType(string(v1.HostPathDirectoryOrCreate))},
			},
			ClaimRef: &v1.ObjectReference{
				Name: "claimA",
			},
		},
	}
	defer os.RemoveAll("foo")

	claim := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claimA",
			Namespace: "nsA",
		},
		Spec: v1.PersistentVolumeClaimSpec{
			VolumeName: "pvA",
		},
		Status: v1.PersistentVolumeClaimStatus{
			Phase: v1.ClaimBound,
		},
	}

	client := fake.NewSimpleClientset(pv, claim)

	plugMgr := volume.VolumePluginMgr{}
	plugMgr.InitPlugins(ProbeVolumePlugins(volume.VolumeConfig{}), nil /* prober */, volumetest.NewFakeVolumeHost("/tmp/fake", client, nil))
	plug, _ := plugMgr.FindPluginByName(hostPathPluginName)

	// readOnly bool is supplied by persistent-claim volume source when its mounter creates other volumes
	spec := volume.NewSpecFromPersistentVolume(pv, true)
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("poduid")}}
	mounter, _ := plug.NewMounter(spec, pod, volume.VolumeOptions{})
	if mounter == nil {
		t.Fatalf("Got a nil Mounter")
	}

	if !mounter.GetAttributes().ReadOnly {
		t.Errorf("Expected true for mounter.IsReadOnly")
	}
}

type fakeFileTypeChecker struct {
	desiredType string
}

func (fftc *fakeFileTypeChecker) getFileType(_ os.FileInfo) (v1.HostPathType, error) {
	return *newHostPathType(fftc.desiredType), nil
}

func setUp() error {
	err := os.MkdirAll("/tmp/ExistingFolder", os.FileMode(0755))
	if err != nil {
		return err
	}

	f, err := os.OpenFile("/tmp/ExistingFolder/foo", os.O_CREATE, os.FileMode(0644))
	defer f.Close()
	if err != nil {
		return err
	}

	return nil
}

func tearDown() {
	os.RemoveAll("/tmp/ExistingFolder")
}

func TestOSFileTypeChecker(t *testing.T) {
	err := setUp()
	if err != nil {
		t.Error(err)
	}
	defer tearDown()
	testCases := []struct {
		name        string
		path        string
		desiredType string
		isDir       bool
		isFile      bool
		isSocket    bool
		isBlock     bool
		isChar      bool
	}{
		{
			name:  "Existing Folder",
			path:  "/tmp/ExistingFolder",
			isDir: true,
		},
		{
			name:   "Existing File",
			path:   "/tmp/ExistingFolder/foo",
			isFile: true,
		},
		{
			name:        "Existing Socket File",
			path:        "/tmp/ExistingFolder/foo",
			desiredType: string(v1.HostPathSocket),
			isSocket:    true,
		},
		{
			name:        "Existing Character Device",
			path:        "/tmp/ExistingFolder/foo",
			desiredType: string(v1.HostPathCharDev),
			isChar:      true,
		},
		{
			name:        "Existing Block Device",
			path:        "/tmp/ExistingFolder/foo",
			desiredType: string(v1.HostPathBlockDev),
			isBlock:     true,
		},
	}

	for i, tc := range testCases {
		oftc, err := newOSFileTypeChecker(tc.path,
			&fakeFileTypeChecker{desiredType: tc.desiredType})
		if err != nil {
			t.Errorf("[%d: %q] expect nil, but got %v", i, tc.name, err)
		}

		path := oftc.GetPath()
		if path != tc.path {
			t.Errorf("[%d: %q] got unexpected path: %s", i, tc.name, path)
		}

		exist := oftc.Exists()
		if !exist {
			t.Errorf("[%d: %q] path: %s does not exist", i, tc.name, path)
		}

		if tc.isDir {
			if !oftc.IsDir() {
				t.Errorf("[%d: %q] expected folder, got unexpected: %s", i, tc.name, path)
			}
			if oftc.IsFile() {
				t.Errorf("[%d: %q] expected folder, got unexpected file: %s", i, tc.name, path)
			}
			if oftc.IsSocket() {
				t.Errorf("[%d: %q] expected folder, got unexpected socket file: %s", i, tc.name, path)
			}
			if oftc.IsBlock() {
				t.Errorf("[%d: %q] expected folder, got unexpected block device: %s", i, tc.name, path)
			}
			if oftc.IsChar() {
				t.Errorf("[%d: %q] expected folder, got unexpected character device: %s", i, tc.name, path)
			}
		}

		if tc.isFile {
			if !oftc.IsFile() {
				t.Errorf("[%d: %q] expected file, got unexpected: %s", i, tc.name, path)
			}
			if oftc.IsDir() {
				t.Errorf("[%d: %q] expected file, got unexpected folder: %s", i, tc.name, path)
			}
			if oftc.IsSocket() {
				t.Errorf("[%d: %q] expected file, got unexpected socket file: %s", i, tc.name, path)
			}
			if oftc.IsBlock() {
				t.Errorf("[%d: %q] expected file, got unexpected block device: %s", i, tc.name, path)
			}
			if oftc.IsChar() {
				t.Errorf("[%d: %q] expected file, got unexpected character device: %s", i, tc.name, path)
			}
		}

		if tc.isSocket {
			if !oftc.IsSocket() {
				t.Errorf("[%d: %q] expected socket file, got unexpected: %s", i, tc.name, path)
			}
			if oftc.IsDir() {
				t.Errorf("[%d: %q] expected socket file, got unexpected folder: %s", i, tc.name, path)
			}
			if !oftc.IsFile() {
				t.Errorf("[%d: %q] expected socket file, got unexpected file: %s", i, tc.name, path)
			}
			if oftc.IsBlock() {
				t.Errorf("[%d: %q] expected socket file, got unexpected block device: %s", i, tc.name, path)
			}
			if oftc.IsChar() {
				t.Errorf("[%d: %q] expected socket file, got unexpected character device: %s", i, tc.name, path)
			}
		}

		if tc.isChar {
			if !oftc.IsChar() {
				t.Errorf("[%d: %q] expected character device, got unexpected: %s", i, tc.name, path)
			}
			if oftc.IsDir() {
				t.Errorf("[%d: %q] expected character device, got unexpected folder: %s", i, tc.name, path)
			}
			if !oftc.IsFile() {
				t.Errorf("[%d: %q] expected character device, got unexpected file: %s", i, tc.name, path)
			}
			if oftc.IsSocket() {
				t.Errorf("[%d: %q] expected character device, got unexpected socket file: %s", i, tc.name, path)
			}
			if oftc.IsBlock() {
				t.Errorf("[%d: %q] expected character device, got unexpected block device: %s", i, tc.name, path)
			}
		}

		if tc.isBlock {
			if !oftc.IsBlock() {
				t.Errorf("[%d: %q] expected block device, got unexpected: %s", i, tc.name, path)
			}
			if oftc.IsDir() {
				t.Errorf("[%d: %q] expected block device, got unexpected folder: %s", i, tc.name, path)
			}
			if !oftc.IsFile() {
				t.Errorf("[%d: %q] expected block device, got unexpected file: %s", i, tc.name, path)
			}
			if oftc.IsSocket() {
				t.Errorf("[%d: %q] expected block device, got unexpected socket file: %s", i, tc.name, path)
			}
			if oftc.IsChar() {
				t.Errorf("[%d: %q] expected block device, got unexpected character device: %s", i, tc.name, path)
			}
		}
	}

}

type fakeHostPathTypeChecker struct {
	name            string
	path            string
	exists          bool
	isDir           bool
	isFile          bool
	isSocket        bool
	isBlock         bool
	isChar          bool
	validpathType   []*v1.HostPathType
	invalidpathType []*v1.HostPathType
}

func (ftc *fakeHostPathTypeChecker) MakeFile() error { return nil }
func (ftc *fakeHostPathTypeChecker) MakeDir() error  { return nil }
func (ftc *fakeHostPathTypeChecker) Exists() bool    { return ftc.exists }
func (ftc *fakeHostPathTypeChecker) IsFile() bool    { return ftc.isFile }
func (ftc *fakeHostPathTypeChecker) IsDir() bool     { return ftc.isDir }
func (ftc *fakeHostPathTypeChecker) IsBlock() bool   { return ftc.isBlock }
func (ftc *fakeHostPathTypeChecker) IsChar() bool    { return ftc.isChar }
func (ftc *fakeHostPathTypeChecker) IsSocket() bool  { return ftc.isSocket }
func (ftc *fakeHostPathTypeChecker) GetPath() string { return ftc.path }

func TestHostPathTypeCheckerInternal(t *testing.T) {
	testCases := []fakeHostPathTypeChecker{
		{
			name:          "Existing Folder",
			path:          "/existingFolder",
			isDir:         true,
			exists:        true,
			validpathType: newHostPathTypeList(string(v1.HostPathDirectoryOrCreate), string(v1.HostPathDirectory)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathFileOrCreate), string(v1.HostPathFile),
				string(v1.HostPathSocket), string(v1.HostPathCharDev), string(v1.HostPathBlockDev)),
		},
		{
			name:          "New Folder",
			path:          "/newFolder",
			isDir:         false,
			exists:        false,
			validpathType: newHostPathTypeList(string(v1.HostPathDirectoryOrCreate)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathDirectory), string(v1.HostPathFile),
				string(v1.HostPathSocket), string(v1.HostPathCharDev), string(v1.HostPathBlockDev)),
		},
		{
			name:          "Existing File",
			path:          "/existingFile",
			isFile:        true,
			exists:        true,
			validpathType: newHostPathTypeList(string(v1.HostPathFileOrCreate), string(v1.HostPathFile)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathDirectoryOrCreate), string(v1.HostPathDirectory),
				string(v1.HostPathSocket), string(v1.HostPathCharDev), string(v1.HostPathBlockDev)),
		},
		{
			name:          "New File",
			path:          "/newFile",
			isFile:        false,
			exists:        false,
			validpathType: newHostPathTypeList(string(v1.HostPathFileOrCreate)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathDirectory),
				string(v1.HostPathSocket), string(v1.HostPathCharDev), string(v1.HostPathBlockDev)),
		},
		{
			name:          "Existing Socket",
			path:          "/existing.socket",
			isSocket:      true,
			isFile:        true,
			exists:        true,
			validpathType: newHostPathTypeList(string(v1.HostPathSocket), string(v1.HostPathFileOrCreate), string(v1.HostPathFile)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathDirectoryOrCreate), string(v1.HostPathDirectory),
				string(v1.HostPathCharDev), string(v1.HostPathBlockDev)),
		},
		{
			name:          "Existing Character Device",
			path:          "/existing.char",
			isChar:        true,
			isFile:        true,
			exists:        true,
			validpathType: newHostPathTypeList(string(v1.HostPathCharDev), string(v1.HostPathFileOrCreate), string(v1.HostPathFile)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathDirectoryOrCreate), string(v1.HostPathDirectory),
				string(v1.HostPathSocket), string(v1.HostPathBlockDev)),
		},
		{
			name:          "Existing Block Device",
			path:          "/existing.block",
			isBlock:       true,
			isFile:        true,
			exists:        true,
			validpathType: newHostPathTypeList(string(v1.HostPathBlockDev), string(v1.HostPathFileOrCreate), string(v1.HostPathFile)),
			invalidpathType: newHostPathTypeList(string(v1.HostPathDirectoryOrCreate), string(v1.HostPathDirectory),
				string(v1.HostPathSocket), string(v1.HostPathCharDev)),
		},
	}

	for i, tc := range testCases {
		for _, pathType := range tc.validpathType {
			err := checkTypeInternal(&tc, pathType)
			if err != nil {
				t.Errorf("[%d: %q] [%q] expected nil, got %v", i, tc.name, string(*pathType), err)
			}
		}

		for _, pathType := range tc.invalidpathType {
			checkResult := checkTypeInternal(&tc, pathType)
			if checkResult == nil {
				t.Errorf("[%d: %q] [%q] expected error, got nil", i, tc.name, string(*pathType))
			}
		}
	}

}
