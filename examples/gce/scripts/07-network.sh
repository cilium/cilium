#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

create_route(){
    route_name=$1
    next_hop=$2
    dest_range=$3
    gcloud compute routes create "kubernetes-route-${route_name}" \
        --network kubernetes \
        --next-hop-address ${next_hop} \
        --destination-range ${dest_range}
}

while read line; do
    route_name=$(echo "$line" | tr "./" - | cut -d' ' -f 2)
    next_hop=$(echo "$line" | cut -d' ' -f 1)
    dest_range=$(echo "$line" | cut -d' ' -f 2)
    create_route ${route_name} ${next_hop} ${dest_range}
done < <(kubectl get nodes \
  --output=jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address} {.spec.podCIDR} {"\n"}{end}')

