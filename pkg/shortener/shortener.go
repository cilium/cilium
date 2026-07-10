// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shortener

import (
	"crypto/sha256"
	"fmt"
)

const (
	// Maximum characters in a K8s resource name
	k8sMaxResourceNameLength = 63

	// Maximum characters in a Hive job name
	hiveMaxJobNameLength = 100
)

func ShortenK8sResourceName(s string) string {
	return shorten(s, k8sMaxResourceNameLength)
}

func ShortenHiveJobName(s string) string {
	return shorten(s, hiveMaxJobNameLength)
}

// Shorten shortens the string to the arbitrary number of characters.
func shorten(s string, length int) string {
	if len(s) > length {
		return s[:length-10-1] + "-" + encodeHash(hash(s))
	}
	return s
}

// encodeHash encodes the first 10 characters of the hex string.
// https://github.com/kubernetes/kubernetes/blob/f0dcf0614036d8c3cd1c9f3b3cf8df4bb1d8e44e/staging/src/k8s.io/kubectl/pkg/util/hash/hash.go#L105
func encodeHash(hex string) string {
	enc := []rune(hex[:10])
	for i := range enc {
		switch enc[i] {
		case '0':
			enc[i] = 'g'
		case '1':
			enc[i] = 'h'
		case '3':
			enc[i] = 'k'
		case 'a':
			enc[i] = 'm'
		case 'e':
			enc[i] = 't'
		}
	}
	return string(enc)
}

// hash hashes `data` with sha256 and returns the hex string
func hash(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}
