// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"fmt"
	"strconv"
	"strings"
)

func maxSequenceNumber(s1 string, s2 string) (string, error) {
	n1, err := sequenceNumberFromString(s1)
	if err != nil {
		return "", err
	}
	n2, err := sequenceNumberFromString(s2)
	if err != nil {
		return "", err
	}
	if n1 >= n2 {
		return s1, nil
	}
	return s2, nil
}

func sequenceNumberFromString(s string) (int64, error) {
	if s == "" || s == "N/A" {
		return 0, nil
	}
	if !strings.HasPrefix(s, "0x") {
		return 0, fmt.Errorf("invalid IPsec sequence number: %s", s)
	}
	parts := strings.Split(s, "/")
	return strconv.ParseInt(parts[0][2:], 16, 64)
}
