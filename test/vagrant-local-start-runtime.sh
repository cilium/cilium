#!/bin/bash

set -e

export K8S_VERSION=${K8S_VERSION:-1.19}

echo "destroying runtime"
vagrant destroy runtime --force 2>/dev/null

if [ "$PRELOAD_VM" != "false" ]; then
    ./vagrant-local-create-box.sh
else
    # Use defaults (see ../vagrant_box_defaults.rb)
    unset SERVER_BOX
    unset SERVER_VERSION
fi

echo "starting runtime vm"
vagrant up runtime --provision
