// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// C2GoArray transforms an hexadecimal string representation into a byte slice.
// Example:
// str := "0x12, 0xff, 0x0, 0x1"
// fmt.Print(C2GoArray(str)) //`{0x12, 0xFF, 0x0, 0x01}`"
func C2GoArray(str string) []byte {
	ret := []byte{}

	if str == "" {
		return ret
	}

	hexStr := strings.Split(str, ", ")
	for _, hexDigit := range hexStr {
		strDigit := strings.TrimPrefix(hexDigit, "0x")
		digitUint64, err := strconv.ParseUint(strDigit, 16, 8)
		if err != nil {
			return nil
		}
		ret = append(ret, byte(digitUint64))
	}
	return ret
}

// GoArray2C transforms a byte slice into its hexadecimal string representation.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2C(array)) // "{ 0x12, 0xff, 0x0, 0x1 }"
func GoArray2C(array []byte) string {
	return goArray2C(array, true)
}

// GoArray2CNoSpaces does the same as GoArray2C, but no spaces are used in
// the final output.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2CNoSpaces(array)) // "{0x12,0xff,0x0,0x1}"
func GoArray2CNoSpaces(array []byte) string {
	return goArray2C(array, false)
}

func goArray2C(array []byte, space bool) string {
	ret := ""
	format := ",%#x"
	if space {
		format = ", %#x"
	}

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(format, e)
		}
	}
	return ret
}

// RequireRootPrivilege checks if the user running cmd is root. If not, it exits the program
func RequireRootPrivilege(cmd string) {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with root privileges.\n", cmd)
		os.Exit(1)
	}
}

// MapStringStructToSlice returns a slice with all keys of the given
// map[string]struct{}
func MapStringStructToSlice(m map[string]struct{}) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

// GetNumPossibleCPUs returns a total number of possible CPUS, i.e. CPUs that
// have been allocated resources and can be brought online if they are present.
// The number is retrieved by parsing /sys/device/system/cpu/possible.
//
// See https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/cpumask.h?h=v4.19#n50
// for more details.
func GetNumPossibleCPUs(log *logrus.Entry) int {
	f, err := os.Open(PossibleCPUSysfsPath)
	if err != nil {
		log.WithError(err).Errorf("unable to open %q", PossibleCPUSysfsPath)
		return 0
	}
	defer f.Close()

	return getNumPossibleCPUsFromReader(log, f)
}

func getNumPossibleCPUsFromReader(log *logrus.Entry, r io.Reader) int {
	out, err := io.ReadAll(r)
	if err != nil {
		log.WithError(err).Errorf("unable to read %q to get CPU count", PossibleCPUSysfsPath)
		return 0
	}

	var start, end int
	count := 0
	for _, s := range strings.Split(string(out), ",") {
		// Go's scanf will return an error if a format cannot be fully matched.
		// So, just ignore it, as a partial match (e.g. when there is only one
		// CPU) is expected.
		n, err := fmt.Sscanf(s, "%d-%d", &start, &end)

		switch n {
		case 0:
			log.WithError(err).Errorf("failed to scan %q to retrieve number of possible CPUs!", s)
			return 0
		case 1:
			count++
		default:
			count += (end - start + 1)
		}
	}

	return count
}
