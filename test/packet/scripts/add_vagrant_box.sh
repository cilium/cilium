#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "usage: add-vagrant-boxes.sh [vagrant_box_defaults.rb path]"
    exit 1
fi

path=$1

for box in SERVER NETNEXT_SERVER; do
    name=$(cat $path | grep "^\$${box}_BOX" | awk '{print $NF}' | sed 's/^"\(.*\)"$/\1/')
    # we need non-dev images for CI
    if [[ "$name" == "cilium/ubuntu-dev" ]]; then
        name="cilium/ubuntu"
    fi

    if [[ "$name" == "" ]]; then
        continue
    fi

    version=$(cat $path |grep "^\$${box}_VERSION" | awk '{print $NF}' | sed 's/^"\(.*\)"$/\1/')

    set +e
	vagrant box list | grep "$name " | grep $version
	if [[ $? -eq 0 ]]; then
		echo "box already exists, no need to preload"
		continue
	fi

    curl --fail http://vagrant-cache.ci.cilium.io/$name/$version/lock
    lock_exit_code=$?
    # check for 404 error indicating that cache is up and lock file is not in place
    if [ $lock_exit_code  -eq 22 ]; then
        download_from_cache=true
    else
        # cache is down or box is locked
        download_from_cache=false
    fi

    box_downloaded=false

    if [[ $download_from_cache == true ]]; then
        echo "adding box from cache"
        curl --fail http://vagrant-cache.ci.cilium.io/$name/$version/metadata.json --output metadata.json
        curl http://vagrant-cache.ci.cilium.io/$name/$version/package.box --output package.box
        vagrant box add metadata.json
        box_downloaded=$?
    fi

    set -e
    if [[ $box_downloaded -ne 0 ]]; then
        echo "box locked or unavailable, adding box from vagrant cloud"
        vagrant box add $name --box-version $version
    fi
done
