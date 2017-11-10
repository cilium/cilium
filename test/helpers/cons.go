// Copyright 2017 Authors of Cilium
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

package helpers

import (
	"fmt"
	"time"
)

var (
	timeout    = 300 * time.Second
	K8s1VMName = fmt.Sprintf("%s-%s", K8s1, GetCurrentK8SEnv())
	K8s2VMName = fmt.Sprintf(fmt.Sprintf("%s-%s", K8s2, GetCurrentK8SEnv()))
)

const (
	basePath = "/home/vagrant/go/src/github.com/cilium/cilium/test"

	// VM / Test suite constants.
	K8s     = "k8s"
	K8s1    = "k8s1"
	K8s2    = "k8s2"
	Runtime = "runtime"

	Enabled  = "enabled"
	Disabled = "disabled"
	Total    = "total"

	// Policy Enforcement flag and accepted values for setting it.
	PolicyEnforcement        = "PolicyEnforcement"
	PolicyEnforcementDefault = "default"
	PolicyEnforcementAlways  = "always"
	PolicyEnforcementNever   = "never"

	// Docker Image names
	CiliumDockerNetwork = "cilium-net"
	NetperfImage        = "tgraf/netperf"
	HttpdImage          = "cilium/demo-httpd"

	// Endpoint names
	Httpd1 = "httpd1"
	Httpd2 = "httpd2"
	Httpd3 = "httpd3"
	App1   = "app1"
	App2   = "app2"
	App3   = "app3"
	Client = "client"
	Server = "server"
	Host   = "host"

	// Lifecycle actions
	Create = "create"
	Delete = "delete"

	// IP Address families.
	IPv4 = "IPv4"
	IPv6 = "IPv6"

	// Configuration options for endpoints. Copied from endpoint/endpoint.go
	// TODO: these should be converted into types for use in configuration
	// functions instead of using basic strings.

	OptionAllowToHost         = "AllowToHost"
	OptionAllowToWorld        = "AllowToWorld"
	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionNAT46               = "NAT46"
	OptionPolicy              = "Policy"

	OptionDisabled = "Disabled"
	OptionEnabled  = "Enabled"

	PingCount          = 5
	CurlConnectTimeout = 5

	DefaultNamespace    = "default"
	KubeSystemNamespace = "kube-system"
)

//GetFilePath returns the absolute path of the provided filename
func GetFilePath(filename string) string {
	return fmt.Sprintf("%s%s", basePath, filename)
}
