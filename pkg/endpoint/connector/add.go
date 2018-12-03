// Copyright 2016-2017 Authors of Cilium
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

package connector

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"golang.org/x/sys/unix"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-connector")

const (
	// hostInterfacePrefix is the Host interface prefix.
	hostInterfacePrefix = "lxc"
	// temporaryInterfacePrefix is the temporary interface prefix while setting up libNetwork interface.
	temporaryInterfacePrefix = "tmp"
)

// Endpoint2IfName returns the host interface name for the given endpointID.
func Endpoint2IfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	// returned string length should be < unix.IFNAMSIZ
	truncateLength := uint(unix.IFNAMSIZ - len(temporaryInterfacePrefix) - 1)
	return hostInterfacePrefix + truncateString(sum, truncateLength)
}

// Endpoint2TempIfName returns the temporary interface name for the given
// endpointID.
func Endpoint2TempIfName(endpointID string) string {
	return temporaryInterfacePrefix + truncateString(endpointID, 5)
}

var ifChars = []rune("abcdefghijklmnopqrstuvwxyz")

func randIfStr(num int) string {
	str := make([]rune, num)
	for i := range str {
		str[i] = ifChars[rand.Intn(len(ifChars))]
	}
	return string(str)
}

// EndpointRandIfName returns a random, temporary interface name for the
// given endpointID. This is similar to Endpoint2TempIfName() but uses a
// random string instead of endpoint ID.
func Endpoint2TempRandIfName() string {
	return temporaryInterfacePrefix + "_" + randIfStr(5)
}

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
}

// WriteSysConfig tries to emulate a sysctl call by writing directly to the
// given fileName the given value.
func WriteSysConfig(fileName, value string) error {
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("unable to open configuration file: %s", err)
	}
	_, err = f.WriteString(value)
	if err != nil {
		f.Close()
		return fmt.Errorf("unable to write value: %s", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("unable to close configuration file: %s", err)
	}
	return nil
}
