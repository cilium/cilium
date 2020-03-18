// Copyright 2020 Authors of Cilium
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

package external_ips

const (
	PublicInterfaceName  = "enp0s10"
	PrivateInterfaceName = "enp0s8"
)

// On both dev and CI VMs the public interface, i.e., an interface that has a
// network shared with the host is the 'enp0s10'. The private interface, i.e.,
// an interface that has a network shared with all VMs is the 'enp0s8'
var NetDevTranslation = map[string]string{
	"svc-a-external-ips-k8s1-host-public":  PublicInterfaceName,
	"svc-b-external-ips-k8s1-host-public":  PublicInterfaceName,
	"svc-a-external-ips-k8s1-host-private": PrivateInterfaceName,
	"svc-b-external-ips-k8s1-host-private": PrivateInterfaceName,
}

type EntryTestArgs struct {
	Description string
	Expected    string
	IP          string
	Port        string
	SkipReason  string
}
