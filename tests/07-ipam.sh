#!/usr/bin/env bash

source "./helpers.bash"

set -e

# Set debug mode on so that we can retrieve the list of IPs allocated
cilium daemon config Debug=true

# Check the list of IPs allocated. The IPv4 IP used on the IPv4 range should be allocated.
if [[ "$(cilium daemon status | tail -n 3)" != \
      "$(echo -e "V4 addresses reserved:\n 10.1.0.1\nV6 addresses reserved:")" ]]; then
     abort "IPs were not properly released"
fi
