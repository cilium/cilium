// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ipcache provides a BPF datapath implementation of the IPCache store.
// It depends on details from pkg/ipcache (which handles IPCache events), as
// well as (indirectly) details such as the KVstore. It is kept distinct from
// pkg/maps/ipcache, which only deals with low-level BPF details of the
// underlying map.
package ipcache
