#!/bin/bash

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker rm -f "$(cat ${script_dir}/registry_container)"
