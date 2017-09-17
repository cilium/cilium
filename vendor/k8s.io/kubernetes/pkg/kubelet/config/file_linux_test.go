// +build linux

/*
Copyright 2016 The Kubernetes Authors.

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

package config

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	utiltesting "k8s.io/client-go/util/testing"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/testapi"
	k8s_api_v1 "k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/api/validation"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/securitycontext"
)

func TestExtractFromNonExistentFile(t *testing.T) {
	ch := make(chan interface{}, 1)
	c := new("/some/fake/file", "localhost", time.Millisecond, ch)
	err := c.watch()
	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestUpdateOnNonExistentFile(t *testing.T) {
	ch := make(chan interface{})
	NewSourceFile("random_non_existent_path", "localhost", time.Millisecond, ch)
	select {
	case got := <-ch:
		update := got.(kubetypes.PodUpdate)
		expected := CreatePodUpdate(kubetypes.SET, kubetypes.FileSource)
		if !apiequality.Semantic.DeepDerivative(expected, update) {
			t.Fatalf("expected %#v, Got %#v", expected, update)
		}

	case <-time.After(wait.ForeverTestTimeout):
		t.Fatalf("expected update, timeout instead")
	}
}

func TestReadPodsFromFileExistAlready(t *testing.T) {
	hostname := types.NodeName("random-test-hostname")
	var testCases = getTestCases(hostname)

	for _, testCase := range testCases {
		func() {
			dirName, err := utiltesting.MkTmpdir("file-test")
			if err != nil {
				t.Fatalf("unable to create temp dir: %v", err)
			}
			defer os.RemoveAll(dirName)
			file := testCase.writeToFile(dirName, "test_pod_manifest", t)

			ch := make(chan interface{})
			NewSourceFile(file, hostname, time.Millisecond, ch)
			select {
			case got := <-ch:
				update := got.(kubetypes.PodUpdate)
				for _, pod := range update.Pods {
					// TODO: remove the conversion when validation is performed on versioned objects.
					internalPod := &api.Pod{}
					if err := k8s_api_v1.Convert_v1_Pod_To_api_Pod(pod, internalPod, nil); err != nil {
						t.Fatalf("%s: Cannot convert pod %#v, %#v", testCase.desc, pod, err)
					}
					if errs := validation.ValidatePod(internalPod); len(errs) > 0 {
						t.Fatalf("%s: Invalid pod %#v, %#v", testCase.desc, internalPod, errs)
					}
				}
				if !apiequality.Semantic.DeepEqual(testCase.expected, update) {
					t.Fatalf("%s: Expected %#v, Got %#v", testCase.desc, testCase.expected, update)
				}
			case <-time.After(wait.ForeverTestTimeout):
				t.Fatalf("%s: Expected update, timeout instead", testCase.desc)
			}
		}()
	}
}

func TestReadPodsFromFileExistLater(t *testing.T) {
	watchFileAdded(false, t)
}

func TestReadPodsFromFileChanged(t *testing.T) {
	watchFileChanged(false, t)
}

func TestReadPodsFromFileInDirAdded(t *testing.T) {
	watchFileAdded(true, t)
}

func TestReadPodsFromFileInDirChanged(t *testing.T) {
	watchFileChanged(true, t)
}

func TestExtractFromBadDataFile(t *testing.T) {
	dirName, err := utiltesting.MkTmpdir("file-test")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}
	defer os.RemoveAll(dirName)

	fileName := filepath.Join(dirName, "test_pod_manifest")
	err = ioutil.WriteFile(fileName, []byte{1, 2, 3}, 0555)
	if err != nil {
		t.Fatalf("unable to write test file %#v", err)
	}

	ch := make(chan interface{}, 1)
	c := new(fileName, "localhost", time.Millisecond, ch)
	err = c.resetStoreFromPath()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectEmptyChannel(t, ch)
}

func TestExtractFromEmptyDir(t *testing.T) {
	dirName, err := utiltesting.MkTmpdir("file-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(dirName)

	ch := make(chan interface{}, 1)
	c := new(dirName, "localhost", time.Millisecond, ch)
	err = c.resetStoreFromPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update := (<-ch).(kubetypes.PodUpdate)
	expected := CreatePodUpdate(kubetypes.SET, kubetypes.FileSource)
	if !apiequality.Semantic.DeepEqual(expected, update) {
		t.Fatalf("expected %#v, Got %#v", expected, update)
	}
}

type testCase struct {
	desc     string
	pod      runtime.Object
	expected kubetypes.PodUpdate
}

func getTestCases(hostname types.NodeName) []*testCase {
	grace := int64(30)
	return []*testCase{
		{
			desc: "Simple pod",
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					UID:       "12345",
					Namespace: "mynamespace",
				},
				Spec: v1.PodSpec{
					Containers:      []v1.Container{{Name: "image", Image: "test/image", SecurityContext: securitycontext.ValidSecurityContextWithContainerDefaults()}},
					SecurityContext: &v1.PodSecurityContext{},
					SchedulerName:   api.DefaultSchedulerName,
				},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
				},
			},
			expected: CreatePodUpdate(kubetypes.SET, kubetypes.FileSource, &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-" + string(hostname),
					UID:         "12345",
					Namespace:   "mynamespace",
					Annotations: map[string]string{kubetypes.ConfigHashAnnotationKey: "12345"},
					SelfLink:    getSelfLink("test-"+string(hostname), "mynamespace"),
				},
				Spec: v1.PodSpec{
					NodeName:                      string(hostname),
					RestartPolicy:                 v1.RestartPolicyAlways,
					DNSPolicy:                     v1.DNSClusterFirst,
					TerminationGracePeriodSeconds: &grace,
					Tolerations: []v1.Toleration{{
						Operator: "Exists",
						Effect:   "NoExecute",
					}},
					Containers: []v1.Container{{
						Name:  "image",
						Image: "test/image",
						TerminationMessagePath:   "/dev/termination-log",
						ImagePullPolicy:          "Always",
						SecurityContext:          securitycontext.ValidSecurityContextWithContainerDefaults(),
						TerminationMessagePolicy: v1.TerminationMessageReadFile,
					}},
					SecurityContext: &v1.PodSecurityContext{},
					SchedulerName:   api.DefaultSchedulerName,
				},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
				},
			}),
		},
	}
}

func (tc *testCase) writeToFile(dir, name string, t *testing.T) string {
	var versionedPod runtime.Object
	err := testapi.Default.Converter().Convert(&tc.pod, &versionedPod, nil)
	if err != nil {
		t.Fatalf("%s: error in versioning the pod: %v", tc.desc, err)
	}
	fileContents, err := runtime.Encode(testapi.Default.Codec(), versionedPod)
	if err != nil {
		t.Fatalf("%s: error in encoding the pod: %v", tc.desc, err)
	}

	fileName := filepath.Join(dir, name)
	if err := writeFile(fileName, []byte(fileContents)); err != nil {
		t.Fatalf("unable to write test file %#v", err)
	}
	return fileName
}

func watchFileAdded(watchDir bool, t *testing.T) {
	hostname := types.NodeName("random-test-hostname")
	var testCases = getTestCases(hostname)

	fileNamePre := "test_pod_manifest"
	for index, testCase := range testCases {
		func() {
			dirName, err := utiltesting.MkTmpdir("dir-test")
			if err != nil {
				t.Fatalf("unable to create temp dir: %v", err)
			}
			defer os.RemoveAll(dirName)
			fileName := fmt.Sprintf("%s_%d", fileNamePre, index)

			ch := make(chan interface{})
			if watchDir {
				NewSourceFile(dirName, hostname, 100*time.Millisecond, ch)
			} else {
				NewSourceFile(filepath.Join(dirName, fileName), hostname, 100*time.Millisecond, ch)
			}
			expectEmptyUpdate(t, ch)

			addFile := func() {
				// Add a file
				testCase.writeToFile(dirName, fileName, t)
			}

			go addFile()

			// For !watchDir: expect an update by SourceFile.resetStoreFromPath().
			// For watchDir: expect at least one update from CREATE & MODIFY inotify event.
			// Shouldn't expect two updates from CREATE & MODIFY because CREATE doesn't guarantee file written.
			// In that case no update will be sent from CREATE event.
			expectUpdate(t, ch, testCase)
		}()
	}
}

func watchFileChanged(watchDir bool, t *testing.T) {
	hostname := types.NodeName("random-test-hostname")
	var testCases = getTestCases(hostname)

	fileNamePre := "test_pod_manifest"
	for index, testCase := range testCases {
		func() {
			dirName, err := utiltesting.MkTmpdir("dir-test")
			fileName := fmt.Sprintf("%s_%d", fileNamePre, index)
			if err != nil {
				t.Fatalf("unable to create temp dir: %v", err)
			}
			defer os.RemoveAll(dirName)

			var file string
			lock := &sync.Mutex{}
			ch := make(chan interface{})
			func() {
				lock.Lock()
				defer lock.Unlock()
				file = testCase.writeToFile(dirName, fileName, t)
			}()

			if watchDir {
				NewSourceFile(dirName, hostname, 100*time.Millisecond, ch)
				defer func() {
					// Remove the file
					deleteFile(dirName, fileName, ch, t)
				}()
			} else {
				NewSourceFile(file, hostname, 100*time.Millisecond, ch)
			}
			// expect an update by SourceFile.resetStoreFromPath()
			expectUpdate(t, ch, testCase)

			changeFile := func() {
				// Edit the file content
				lock.Lock()
				defer lock.Unlock()

				pod := testCase.pod.(*v1.Pod)
				pod.Spec.Containers[0].Name = "image2"

				testCase.expected.Pods[0].Spec.Containers[0].Name = "image2"
				testCase.writeToFile(dirName, fileName, t)
			}

			go changeFile()
			// expect an update by MODIFY inotify event
			expectUpdate(t, ch, testCase)

			if watchDir {
				from := fileName
				fileName = fileName + "_ch"
				go changeFileName(dirName, from, fileName, t)
				// expect an update by MOVED_FROM inotify event cause changing file name
				expectEmptyUpdate(t, ch)
				// expect an update by MOVED_TO inotify event cause changing file name
				expectUpdate(t, ch, testCase)
			}
		}()
	}
}

func deleteFile(dir, file string, ch chan interface{}, t *testing.T) {
	go func() {
		path := filepath.Join(dir, file)
		err := os.Remove(path)
		if err != nil {
			t.Errorf("unable to remove test file %s: %s", path, err)
		}
	}()

	expectEmptyUpdate(t, ch)
}

func expectUpdate(t *testing.T, ch chan interface{}, testCase *testCase) {
	timer := time.After(5 * time.Second)
	for {
		select {
		case got := <-ch:
			update := got.(kubetypes.PodUpdate)
			for _, pod := range update.Pods {
				// TODO: remove the conversion when validation is performed on versioned objects.
				internalPod := &api.Pod{}
				if err := k8s_api_v1.Convert_v1_Pod_To_api_Pod(pod, internalPod, nil); err != nil {
					t.Fatalf("%s: Cannot convert pod %#v, %#v", testCase.desc, pod, err)
				}
				if errs := validation.ValidatePod(internalPod); len(errs) > 0 {
					t.Fatalf("%s: Invalid pod %#v, %#v", testCase.desc, internalPod, errs)
				}
			}

			if !apiequality.Semantic.DeepEqual(testCase.expected, update) {
				t.Fatalf("%s: Expected: %#v, Got: %#v", testCase.desc, testCase.expected, update)
			}
			return
		case <-timer:
			t.Fatalf("%s: Expected update, timeout instead", testCase.desc)
		}
	}
}

func expectEmptyUpdate(t *testing.T, ch chan interface{}) {
	timer := time.After(5 * time.Second)
	for {
		select {
		case got := <-ch:
			update := got.(kubetypes.PodUpdate)
			if len(update.Pods) != 0 {
				t.Fatalf("expected empty update, got %#v", update)
			}
			return
		case <-timer:
			t.Fatalf("expected empty update, timeout instead")
		}
	}
}

func writeFile(filename string, data []byte) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func changeFileName(dir, from, to string, t *testing.T) {
	fromPath := filepath.Join(dir, from)
	toPath := filepath.Join(dir, to)
	if err := exec.Command("mv", fromPath, toPath).Run(); err != nil {
		t.Errorf("Fail to change file name: %s", err)
	}
}
