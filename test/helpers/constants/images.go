// Copyright 2017-2019 Authors of Cilium
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

	// MemcachedImage is the image used to test memcached in the runtime tests.
	MemcacheDImage = "docker.io/library/memcached:1.6.6-alpine"

	// MemcacheBinClient is the image used during binary memcached parser tests.
	MemcacheBinClient = "docker.io/cilium/python-bmemcached:v0.0.2"

	// AlpineImage is used during the memcached tests as the text client.
	// Do not upgrade to alpine 3.13 as its nslookup tool returns 1, instead of 0
	// for domain name lookups.
	AlpineImage = "docker.io/library/alpine:3.12.7@sha256:36553b10a4947067b9fbb7d532951066293a68eae893beba1d9235f7d11a20ad"

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
	MemcacheDImage:       {},
	MemcacheBinClient:    {},
	AlpineImage:          {},
	CassandraImage:       {},
	KafkaImage:           {},
}
