#!/bin/bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "$(${script_dir}/../print-node-ip.sh):$(cat ${script_dir}/registry_port)"
