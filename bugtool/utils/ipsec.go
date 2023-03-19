// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// Note that `auth-trunc` is also a relevant pattern, but we already match on the more generic
// `auth` pattern.
var isEncryptionKey = regexp.MustCompile("(auth|enc|aead|comp)(.*[[:blank:]](0[xX][[:xdigit:]]+))?")

// HashEncryptionKeys processes the buffer containing the output of `ip -s xfrm state`.
// It searches for IPsec keys in the output and replaces them by their hash.
func HashEncryptionKeys(output []byte) []byte {
	var b bytes.Buffer
	lines := bytes.Split(output, []byte("\n"))
	// Search for lines containing encryption keys.
	for i, line := range lines {
		// isEncryptionKey.FindStringSubmatchIndex(line) will return:
		// - [], if the global pattern is not found
		// - a slice of integers, if the global pattern is found. The
		//   first two integers are the start and end offsets of the
		//   global pattern. The remaining integers are the start and
		//   end offset of each submatch group (delimited in the
		//   regular expressions by parenthesis).
		//
		// If the global pattern is found, the start and end offset of
		// the hexadecimal string (the third submatch) will be at index
		// 6 and 7 in the slice. They may be equal to -1 if the
		// submatch, marked as optional ('?'), is not found.
		matched := isEncryptionKey.FindSubmatchIndex(line)
		if matched != nil && matched[6] > 0 {
			key := line[matched[6]:matched[7]]
			h := sha256.New()
			h.Write(key)
			sum := h.Sum(nil)
			hashedKey := make([]byte, hex.EncodedLen(len(sum)))
			hex.Encode(hashedKey, sum)
			fmt.Fprintf(&b, "%s[hash:%s]%s", line[:matched[6]], hashedKey, line[matched[7]:])
		} else if matched != nil && matched[6] < 0 {
			b.WriteString("[redacted]")
		} else {
			b.Write(line)
		}
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}
