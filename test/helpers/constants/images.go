// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package constants

const (
	// NetperfImage is the Docker image used for performance testing
	// NB: this image includes netperf and a utility named xping that works
	// like ping but it also allows to specify the ICMP id.
	NetperfImage = "quay.io/cilium/net-test:v1.0.0"

	// HttpdImage is the image used for starting an HTTP server.
	HttpdImage = "docker.io/cilium/demo-httpd:1.0"

	// DNSSECContainerImage is the image used for starting a DNSSec client.
	DNSSECContainerImage = "docker.io/cilium/dnssec-client:v0.2"

	// BindContainerImage is the image used for DNS binding testing.
	BindContainerImage = "docker.io/cilium/docker-bind:v0.3"
)

// AllImages is the set of all container images which are ran directly via
// `docker run` in the Cilium CI. It is used to provide a central location in
// the code of all images that are used.
var AllImages = map[string]struct{}{
	NetperfImage:         {},
	HttpdImage:           {},
	DNSSECContainerImage: {},
	BindContainerImage:   {},
}
