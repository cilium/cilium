// Copyright 2018 Authors of Cilium
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

// Package ipcache provides a BPF datapath implementation of the IPCache store.
// It depends on details from pkg/ipcache (which handles IPCache events), as
// well as (indirectly) details such as the KVstore. It is kept distinct from
// pkg/maps/ipcache, which only deals with low-level BPF details of the
// underlying map.
package ipcache
