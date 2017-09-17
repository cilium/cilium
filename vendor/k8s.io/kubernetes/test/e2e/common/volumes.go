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

/*
 * This test checks that various VolumeSources are working.
 *
 * There are two ways, how to test the volumes:
 * 1) With containerized server (NFS, Ceph, Gluster, iSCSI, ...)
 * The test creates a server pod, exporting simple 'index.html' file.
 * Then it uses appropriate VolumeSource to import this file into a client pod
 * and checks that the pod can see the file. It does so by importing the file
 * into web server root and loadind the index.html from it.
 *
 * These tests work only when privileged containers are allowed, exporting
 * various filesystems (NFS, GlusterFS, ...) usually needs some mounting or
 * other privileged magic in the server pod.
 *
 * Note that the server containers are for testing purposes only and should not
 * be used in production.
 *
 * 2) With server outside of Kubernetes (Cinder, ...)
 * Appropriate server (e.g. OpenStack Cinder) must exist somewhere outside
 * the tested Kubernetes cluster. The test itself creates a new volume,
 * and checks, that Kubernetes can use it as a volume.
 */

// GlusterFS test is duplicated from test/e2e/volumes.go.  Any changes made there
// should be duplicated here

package common

import (
	"k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// These tests need privileged containers, which are disabled by default.  Run
// the test with "go run hack/e2e.go ... --ginkgo.focus=[Feature:Volumes]"
var _ = Describe("[sig-storage] GCP Volumes", func() {
	f := framework.NewDefaultFramework("gcp-volume")

	// If 'false', the test won't clear its volumes upon completion. Useful for debugging,
	// note that namespace deletion is handled by delete-namespace flag
	clean := true
	// filled in BeforeEach
	var namespace *v1.Namespace
	var c clientset.Interface

	BeforeEach(func() {
		framework.SkipUnlessNodeOSDistroIs("gci", "ubuntu")

		namespace = f.Namespace
		c = f.ClientSet
	})

	////////////////////////////////////////////////////////////////////////
	// NFS
	////////////////////////////////////////////////////////////////////////
	Describe("NFSv4", func() {
		It("should be mountable for NFSv4", func() {
			config, _, serverIP := framework.NewNFSServer(c, namespace.Name, []string{})
			defer func() {
				if clean {
					framework.VolumeTestCleanup(f, config)
				}
			}()

			tests := []framework.VolumeTest{
				{
					Volume: v1.VolumeSource{
						NFS: &v1.NFSVolumeSource{
							Server:   serverIP,
							Path:     "/",
							ReadOnly: true,
						},
					},
					File:            "index.html",
					ExpectedContent: "Hello from NFS!",
				},
			}

			// Must match content of test/images/volumes-tester/nfs/index.html
			framework.TestVolumeClient(c, config, nil, tests)
		})
	})

	Describe("NFSv3", func() {
		It("should be mountable for NFSv3", func() {
			config, _, serverIP := framework.NewNFSServer(c, namespace.Name, []string{})
			defer func() {
				if clean {
					framework.VolumeTestCleanup(f, config)
				}
			}()

			tests := []framework.VolumeTest{
				{
					Volume: v1.VolumeSource{
						NFS: &v1.NFSVolumeSource{
							Server:   serverIP,
							Path:     "/exports",
							ReadOnly: true,
						},
					},
					File:            "index.html",
					ExpectedContent: "Hello from NFS!",
				},
			}
			// Must match content of test/images/volume-tester/nfs/index.html
			framework.TestVolumeClient(c, config, nil, tests)
		})
	})

	////////////////////////////////////////////////////////////////////////
	// Gluster
	////////////////////////////////////////////////////////////////////////
	Describe("GlusterFS", func() {
		It("should be mountable", func() {
			// create gluster server and endpoints
			config, _, _ := framework.NewGlusterfsServer(c, namespace.Name)
			name := config.Prefix + "-server"
			defer func() {
				if clean {
					framework.VolumeTestCleanup(f, config)
					err := c.Core().Endpoints(namespace.Name).Delete(name, nil)
					Expect(err).NotTo(HaveOccurred(), "defer: Gluster delete endpoints failed")
				}
			}()

			tests := []framework.VolumeTest{
				{
					Volume: v1.VolumeSource{
						Glusterfs: &v1.GlusterfsVolumeSource{
							EndpointsName: name,
							// 'test_vol' comes from test/images/volumes-tester/gluster/run_gluster.sh
							Path:     "test_vol",
							ReadOnly: true,
						},
					},
					File: "index.html",
					// Must match content of test/images/volumes-tester/gluster/index.html
					ExpectedContent: "Hello from GlusterFS!",
				},
			}
			framework.TestVolumeClient(c, config, nil, tests)
		})
	})
})
