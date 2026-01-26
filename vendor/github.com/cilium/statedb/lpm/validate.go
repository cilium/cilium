// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lpm

import (
	"fmt"
	"os"
)

var runValidation = os.Getenv("STATEDB_VALIDATE") != ""

func validateTrieRoot[T any](node *lpmNode[T], size int, maxTxnID uint64) {
	if !runValidation {
		return
	}

	assert := func(b bool, f string, args ...any) {
		if !b {
			panic(fmt.Sprintf(f, args...))
		}
	}

	if size == 0 {
		assert(node == nil, "non-nil root with size 0")
		return
	}
	assert(node != nil, "nil root with size %d", size)

	count := validateTrie(node, nil, maxTxnID)
	assert(count == size, "size mismatch: tree has %d values, size=%d", count, size)
}

func validateTrie[T any](node *lpmNode[T], parents []*lpmNode[T], maxTxnID uint64) int {
	if node == nil {
		return 0
	}

	assert := func(b bool, f string, args ...any) {
		if !b {
			panic(fmt.Sprintf(f, args...))
		}
	}

	data, prefixLen := DecodeLPMKey(node.key)
	dataLen := int((prefixLen + 7) / 8)
	assert(len(node.key) == dataLen+2, "key length mismatch for %s", showKey(node.key))
	assert(len(data) == dataLen, "key data length mismatch for %s", showKey(node.key))

	if maxTxnID > 0 {
		assert(node.txnID <= maxTxnID, "node txnID %d exceeds max %d (key %s)", node.txnID, maxTxnID, showKey(node.key))
	}

	if len(parents) > 0 {
		parent := parents[len(parents)-1]
		parentPrefixLen := parent.prefixLen()
		assert(prefixLen > parentPrefixLen, "child prefix <= parent prefix (%d <= %d) at %s", prefixLen, parentPrefixLen, showKey(node.key))
		matchLen := longestMatch(PrefixLen(0), parent, data, prefixLen)
		assert(matchLen == parentPrefixLen, "parent prefix mismatch for %s", showKey(node.key))
		assert(parent.txnID >= node.txnID, "parent txnID %d < child txnID %d at %s", parent.txnID, node.txnID, showKey(node.key))
	}

	if node.imaginary {
		assert(node.children[0] != nil && node.children[1] != nil, "imaginary node missing child at %s", showKey(node.key))
	}

	for idx, child := range node.children {
		if child == nil {
			continue
		}
		childData, childPrefixLen := DecodeLPMKey(child.key)
		assert(childPrefixLen > prefixLen, "child prefix <= parent prefix (%d <= %d) at %s", childPrefixLen, prefixLen, showKey(child.key))
		matchLen := longestMatch(PrefixLen(0), node, childData, childPrefixLen)
		assert(matchLen == prefixLen, "child prefix mismatch for %s", showKey(child.key))
		expectedIdx := getBitAt(childData, prefixLen)
		assert(expectedIdx == idx, "child index mismatch at %s", showKey(child.key))
	}

	parents = append(parents, node)
	count := 0
	if !node.imaginary {
		count++
	}
	for _, child := range node.children {
		if child != nil {
			count += validateTrie(child, parents, maxTxnID)
		}
	}
	return count
}
