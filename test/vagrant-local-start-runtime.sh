#!/usr/bin/env bash

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

if [[ "$NFS" != "0" ]]; then
    echo "# NFS enabled. don't forget to enable these ports on your host"
    echo "# before starting the VMs in order to have nfs working"
    echo "# iptables -I INPUT -s 192.168.58.0/24 -j ACCEPT"
fi

echo "starting runtime vm"
vagrant up runtime --provision
