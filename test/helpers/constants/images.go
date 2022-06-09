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

	// KafkaClientImage is the image used for Kafka clients.
	KafkaClientImage = "docker.io/cilium/kafkaclient2:1.0"

	// Zookeeper image is the image used for running Zookeeper.
	ZookeeperImage = "docker.io/cilium/zookeeper:1.0"

	// BuxyboxImage is a space efficient-image used for basic testing.
	BusyboxImage = "docker.io/library/busybox:1.31.1"

	// AlpineCurlImage is the image used for invoking curl with a small base image.
	AlpineCurlImage = "quay.io/cilium/alpine-curl:v1.3.0@sha256:1d928912e5d9dc9994b038b5df7434790c4bb9bd64f60570d78c1dee13befc76"

	// CassandraImage is the image used for testing of the cassandra proxy
	// functionality in Cilium.
	CassandraImage = "docker.io/library/cassandra:3.11.3"

	// KafkaImage is the image used for setting up a multi-broker Kafka container.
	KafkaImage = "docker.io/wurstmeister/kafka:2.11-0.11.0.3"
)

// AllImages is the set of all container images which are ran directly via
// `docker run` in the Cilium CI. It is used to provide a central location in
// the code of all images that are used.
var AllImages = map[string]struct{}{
	NetperfImage:         {},
	HttpdImage:           {},
	DNSSECContainerImage: {},
	BindContainerImage:   {},
	KafkaClientImage:     {},
	ZookeeperImage:       {},
	BusyboxImage:         {},
	AlpineCurlImage:      {},
	CassandraImage:       {},
	KafkaImage:           {},
}
