IP4RANGE="172.20.0.0/16"
IP6RANGE="fd00:10:64::/64"

# A CIDR range inside the networks range, not overlapping with first IPs which will be
# allocated to kind and the gateway.
IP4EXTERNALRANGE="172.20.1.0/24"
IP6EXTERNALRANGE="fd00:10:64::ffff:00/112"

echo "ipv4_external_cidr=$IP4EXTERNALRANGE" >> $GITHUB_OUTPUT
echo "ipv6_external_cidr=$IP6EXTERNALRANGE" >> $GITHUB_OUTPUT

# Recognizable IPs inside the external CIDR
IP4TARGET="172.20.1.100"
IP4OTHERTARGET="172.20.1.101"
IP6TARGET="fd00:10:64::ffff:ec"
IP6OTHERTARGET="fd00:10:64::ffff:ee"

echo "ipv4_external_target=$IP4TARGET" >> $GITHUB_OUTPUT
echo "ipv4_other_external_target=$IP4OTHERTARGET" >> $GITHUB_OUTPUT
echo "ipv6_external_target=$IP6TARGET" >> $GITHUB_OUTPUT
echo "ipv6_other_external_target=$IP6OTHERTARGET" >> $GITHUB_OUTPUT

# Create an external network in the similar way to the one created by kind
# Except we explicitly request subnets which will allow us to allocate specific
# IPs for containers later on. (docker does not allow this for non-manually created networks)
KINDNETWORK="external"
MTU=$(docker network inspect bridge -f '{{ index .Options "com.docker.network.driver.mtu" }}')
docker network create \
    --ipv6 \
    --driver bridge \
    -o com.docker.network.bridge.enable_ip_masquerade=true \
    -o com.docker.network.driver.mtu=$MTU \
    --subnet $IP4RANGE --subnet $IP6RANGE $KINDNETWORK

# Write name of network to action output, for use in other steps
echo "kind_network=$KINDNETWORK" >> $GITHUB_OUTPUT

# Write name of network to environment variable, should be picked up
# by kind when creating the cluster.
echo "KIND_EXPERIMENTAL_DOCKER_NETWORK=$KINDNETWORK" >> $GITHUB_ENV
