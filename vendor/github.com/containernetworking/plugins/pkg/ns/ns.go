// Copyright 2015 CNI authors
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
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
)

type NetNS interface {
	// Executes the passed closure in this object's network namespace,
	// attempting to restore the original namespace before returning.
	// However, since each OS thread can have a different network namespace,
	// and Go's thread scheduling is highly variable, callers cannot
	// guarantee any specific namespace is set unless operations that
	// require that namespace are wrapped with Do().  Also, no code called
	// from Do() should call runtime.UnlockOSThread(), or the risk
	// of executing code in an incorrect namespace will be greater.  See
	// https://github.com/golang/go/wiki/LockOSThread for further details.
	Do(toRun func(NetNS) error) error

	// Sets the current network namespace to this object's network namespace.
	// Note that since Go's thread scheduling is highly variable, callers
	// cannot guarantee the requested namespace will be the current namespace
	// after this function is called; to ensure this wrap operations that
	// require the namespace with Do() instead.
	Set() error

	// Returns the filesystem path representing this object's network namespace
	Path() string

	// Returns a file descriptor representing this object's network namespace
	Fd() uintptr

	// Cleans up this instance of the network namespace; if this instance
	// is the last user the namespace will be destroyed
	Close() error
}

type netNS struct {
	file    *os.File
	mounted bool
	closed  bool
}

// netNS implements the NetNS interface
var _ NetNS = &netNS{}

const (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
	NSFS_MAGIC   = 0x6e736673
	PROCFS_MAGIC = 0x9fa0
)

type NSPathNotExistErr struct{ msg string }

func (e NSPathNotExistErr) Error() string { return e.msg }

type NSPathNotNSErr struct{ msg string }

func (e NSPathNotNSErr) Error() string { return e.msg }

func IsNSorErr(nspath string) error {
	stat := syscall.Statfs_t{}
	if err := syscall.Statfs(nspath, &stat); err != nil {
		if os.IsNotExist(err) {
			err = NSPathNotExistErr{msg: fmt.Sprintf("failed to Statfs %q: %v", nspath, err)}
		} else {
			err = fmt.Errorf("failed to Statfs %q: %v", nspath, err)
		}
		return err
	}

	switch stat.Type {
	case PROCFS_MAGIC, NSFS_MAGIC:
		return nil
	default:
		return NSPathNotNSErr{msg: fmt.Sprintf("unknown FS magic on %q: %x", nspath, stat.Type)}
	}
}

// Returns an object representing the namespace referred to by @path
func GetNS(nspath string) (NetNS, error) {
	err := IsNSorErr(nspath)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(nspath)
	if err != nil {
		return nil, err
	}

	return &netNS{file: fd}, nil
}

func (ns *netNS) Path() string {
	return ns.file.Name()
}

func (ns *netNS) Fd() uintptr {
	return ns.file.Fd()
}

func (ns *netNS) errorIfClosed() error {
	if ns.closed {
		return fmt.Errorf("%q has already been closed", ns.file.Name())
	}
	return nil
}

func (ns *netNS) Do(toRun func(NetNS) error) error {
	if err := ns.errorIfClosed(); err != nil {
		return err
	}

	containedCall := func(hostNS NetNS) error {
		threadNS, err := GetCurrentNS()
		if err != nil {
			return fmt.Errorf("failed to open current netns: %v", err)
		}
		defer threadNS.Close()

		// switch to target namespace
		if err = ns.Set(); err != nil {
			return fmt.Errorf("error switching to ns %v: %v", ns.file.Name(), err)
		}
		defer threadNS.Set() // switch back

		return toRun(hostNS)
	}

	// save a handle to current network namespace
	hostNS, err := GetCurrentNS()
	if err != nil {
		return fmt.Errorf("Failed to open current namespace: %v", err)
	}
	defer hostNS.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	var innerError error
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		innerError = containedCall(hostNS)
	}()
	wg.Wait()

	return innerError
}

// WithNetNSPath executes the passed closure under the given network
// namespace, restoring the original namespace afterwards.
func WithNetNSPath(nspath string, toRun func(NetNS) error) error {
	ns, err := GetNS(nspath)
	if err != nil {
		return err
	}
	defer ns.Close()
	return ns.Do(toRun)
}
