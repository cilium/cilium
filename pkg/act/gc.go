// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

type gcEntry struct {
	unix int64
	svc  uint16
	zone uint8
}

type gcHeap []gcEntry

func (h gcHeap) Len() int           { return len(h) }
func (h gcHeap) Less(i, j int) bool { return h[i].unix > h[j].unix }
func (h gcHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *gcHeap) Push(x any) {
	*h = append(*h, x.(gcEntry))
}

func (h *gcHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
