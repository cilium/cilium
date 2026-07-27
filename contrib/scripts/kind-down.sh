#!/usr/bin/env bash

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

delete_containers="${DELETE_CONTAINERS:-false}"
default_cluster_name="kind"
default_network="kind-cilium"
secondary_network="${default_network}-secondary"

for cluster in "${@:-${default_cluster_name}}"; do
    kind delete cluster --name "$cluster"
done

networks=( "${default_network}" "${secondary_network}" )
for network in "${networks[@]}"
do
  if docker network inspect "${network}" >/dev/null 2>&1; then
      if [[ "$delete_containers" == "true" ]]; then
          echo "Deleting containers attached to network ${network}"
          docker network inspect ${network} | jq -r '.[0].Containers[] | .Name' | xargs docker rm -f
      fi

      docker network rm ${network}
  fi
done
