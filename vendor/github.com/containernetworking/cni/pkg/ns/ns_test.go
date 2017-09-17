// Copyright 2016 CNI authors
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

package ns_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/ns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

func getInodeCurNetNS() (uint64, error) {
	curNS, err := ns.GetCurrentNS()
	if err != nil {
		return 0, err
	}
	defer curNS.Close()
	return getInodeNS(curNS)
}

func getInodeNS(netns ns.NetNS) (uint64, error) {
	return getInodeFd(int(netns.Fd()))
}

func getInode(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return getInodeFd(int(file.Fd()))
}

func getInodeFd(fd int) (uint64, error) {
	stat := &unix.Stat_t{}
	err := unix.Fstat(fd, stat)
	return stat.Ino, err
}

var _ = Describe("Linux namespace operations", func() {
	Describe("WithNetNS", func() {
		var (
			originalNetNS ns.NetNS
			targetNetNS   ns.NetNS
		)

		BeforeEach(func() {
			var err error

			originalNetNS, err = ns.NewNS()
			Expect(err).NotTo(HaveOccurred())

			targetNetNS, err = ns.NewNS()
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(targetNetNS.Close()).To(Succeed())
			Expect(originalNetNS.Close()).To(Succeed())
		})

		It("executes the callback within the target network namespace", func() {
			expectedInode, err := getInodeNS(targetNetNS)
			Expect(err).NotTo(HaveOccurred())

			err = targetNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				actualInode, err := getInodeCurNetNS()
				Expect(err).NotTo(HaveOccurred())
				Expect(actualInode).To(Equal(expectedInode))
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("provides the original namespace as the argument to the callback", func() {
			// Ensure we start in originalNetNS
			err := originalNetNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				origNSInode, err := getInodeNS(originalNetNS)
				Expect(err).NotTo(HaveOccurred())

				err = targetNetNS.Do(func(hostNS ns.NetNS) error {
					defer GinkgoRecover()

					hostNSInode, err := getInodeNS(hostNS)
					Expect(err).NotTo(HaveOccurred())
					Expect(hostNSInode).To(Equal(origNSInode))
					return nil
				})
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the callback returns an error", func() {
			It("restores the calling thread to the original namespace before returning", func() {
				err := originalNetNS.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					preTestInode, err := getInodeCurNetNS()
					Expect(err).NotTo(HaveOccurred())

					_ = targetNetNS.Do(func(ns.NetNS) error {
						return errors.New("potato")
					})

					postTestInode, err := getInodeCurNetNS()
					Expect(err).NotTo(HaveOccurred())
					Expect(postTestInode).To(Equal(preTestInode))
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the error from the callback", func() {
				err := targetNetNS.Do(func(ns.NetNS) error {
					return errors.New("potato")
				})
				Expect(err).To(MatchError("potato"))
			})
		})

		Describe("validating inode mapping to namespaces", func() {
			It("checks that different namespaces have different inodes", func() {
				origNSInode, err := getInodeNS(originalNetNS)
				Expect(err).NotTo(HaveOccurred())

				testNsInode, err := getInodeNS(targetNetNS)
				Expect(err).NotTo(HaveOccurred())

				Expect(testNsInode).NotTo(Equal(0))
				Expect(testNsInode).NotTo(Equal(origNSInode))
			})

			It("should not leak a closed netns onto any threads in the process", func() {
				By("creating a new netns")
				createdNetNS, err := ns.NewNS()
				Expect(err).NotTo(HaveOccurred())

				By("discovering the inode of the created netns")
				createdNetNSInode, err := getInodeNS(createdNetNS)
				Expect(err).NotTo(HaveOccurred())
				createdNetNS.Close()

				By("comparing against the netns inode of every thread in the process")
				for _, netnsPath := range allNetNSInCurrentProcess() {
					netnsInode, err := getInode(netnsPath)
					Expect(err).NotTo(HaveOccurred())
					Expect(netnsInode).NotTo(Equal(createdNetNSInode))
				}
			})

			It("fails when the path is not a namespace", func() {
				tempFile, err := ioutil.TempFile("", "nstest")
				Expect(err).NotTo(HaveOccurred())
				defer tempFile.Close()

				nspath := tempFile.Name()
				defer os.Remove(nspath)

				_, err = ns.GetNS(nspath)
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeAssignableToTypeOf(ns.NSPathNotNSErr{}))
				Expect(err).NotTo(BeAssignableToTypeOf(ns.NSPathNotExistErr{}))
			})
		})

		Describe("closing a network namespace", func() {
			It("should prevent further operations", func() {
				createdNetNS, err := ns.NewNS()
				Expect(err).NotTo(HaveOccurred())

				err = createdNetNS.Close()
				Expect(err).NotTo(HaveOccurred())

				err = createdNetNS.Do(func(ns.NetNS) error { return nil })
				Expect(err).To(HaveOccurred())

				err = createdNetNS.Set()
				Expect(err).To(HaveOccurred())
			})

			It("should only work once", func() {
				createdNetNS, err := ns.NewNS()
				Expect(err).NotTo(HaveOccurred())

				err = createdNetNS.Close()
				Expect(err).NotTo(HaveOccurred())

				err = createdNetNS.Close()
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("IsNSorErr", func() {
		It("should detect a namespace", func() {
			createdNetNS, err := ns.NewNS()
			err = ns.IsNSorErr(createdNetNS.Path())
			Expect(err).NotTo(HaveOccurred())
		})

		It("should refuse other paths", func() {
			tempFile, err := ioutil.TempFile("", "nstest")
			Expect(err).NotTo(HaveOccurred())
			defer tempFile.Close()

			nspath := tempFile.Name()
			defer os.Remove(nspath)

			err = ns.IsNSorErr(nspath)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(ns.NSPathNotNSErr{}))
			Expect(err).NotTo(BeAssignableToTypeOf(ns.NSPathNotExistErr{}))
		})

		It("should error on non-existing paths", func() {
			err := ns.IsNSorErr("/tmp/IDoNotExist")
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(ns.NSPathNotExistErr{}))
			Expect(err).NotTo(BeAssignableToTypeOf(ns.NSPathNotNSErr{}))
		})
	})
})

func allNetNSInCurrentProcess() []string {
	pid := unix.Getpid()
	paths, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/ns/net", pid))
	Expect(err).NotTo(HaveOccurred())
	return paths
}
