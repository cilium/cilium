#!/usr/bin/env bash

set -euo pipefail

check_cmd() {
    for cmd in "$@" ; do
        if ! (command -v "$cmd" >/dev/null) ; then
            echo "Error: $cmd not found."
            exit 1
        fi
    done
}
check_cmd curl vagrant

usage() {
    echo -e "usage: add_vagrant_box.sh [options] [vagrant_box_defaults.rb path]"
    echo -e "\tpath to vagrant_box_defaults.rb defaults to ./vagrant_box_defaults.rb"
    echo -e ""
    echo -e "options:"
    echo -e "\t-a\t\tuse aria2c instead of curl"
    echo -e "\t-b <box>\tdownload selected box (defaults: ubuntu ubuntu-next)"
    echo -e "\t-d <dir>\tdownload to dir instead of /tmp/"
    echo -e "\t-l\t\tdownload latest versions instead of using vagrant_box_defaults"
    echo -e "\t-h\t\tdisplay this help"
    echo -e ""
    echo -e "examples:"
    echo -e "\tdownload boxes ubuntu and ubuntu-next from vagrant_box_defaults.rb:"
    echo -e "\t\$ add_vagrant_box.sh \$HOME/go/src/github.com/cilium/cilium/vagrant_box_defaults.rb"
    echo -e "\tdownload latest version for ubuntu-dev and ubuntu-next:"
    echo -e "\t\$ add_vagrant_box.sh -l -b ubuntu-dev -b ubuntu-next"
    echo -e "\tsame as above, downloading into /tmp/foo and using aria2c:"
    echo -e "\t\$ add_vagrant_box.sh -al -d /tmp/foo -b ubuntu-dev -b ubuntu-next"
    exit 1
}

boxes="ubuntu ubuntu-dev"
box_dir="$HOME/.vagrant.d/boxes/cilium-VAGRANTSLASH-"
box_info="https://app.vagrantup.com/api/v1/search?q=cilium/"
vagrant_url="http://vagrant-cache.ci.cilium.io/cilium/"
version=0
custom_types=0
latest=0
use_aria2=0
aria2c="aria2c -x16 -s16 -c --auto-file-renaming=false --console-log-level=warn --summary-interval=0"
outdir="/tmp"
path=/dev/null

OPTIND=1
while getopts "ab:hld:" opt; do
    case "$opt" in
    h)
        usage 0
        ;;
    a)
        check_cmd aria2c
        use_aria2=1
        ;;
    l)
        check_cmd jq
        latest=1
        ;;
    d)
        outdir="$OPTARG"
        ;;
    b)
        if [[ $custom_types -eq 0 ]] ; then
            boxes=""
        fi
        custom_types=1
        boxes="$boxes $OPTARG"
        ;;
    *)
        echo -e "invalid option: $opt"
        exit 1
    esac
done
shift $((OPTIND-1))
[[ "${1:-}" = "--" ]] && shift

if [[ $latest -ne 1 ]] ; then
    if [[ $# -lt 1 ]] ; then
        if [[ -f ./vagrant_box_defaults.rb ]] ; then
            path=vagrant_box_defaults.rb
        else
            usage 1
        fi
    else
        path=$1
    fi
fi

check_defaults_version() {
    version=$(sed -n '/'$1'"$/{n;s/.*"\(.*\)"$/\1/p;q}' "$path")
    found=1

    vagrant box list | grep "$box " | grep "$version" || found=0
    if [[ $found -eq 1 ]]; then
        echo -e "$box:\tfound version $version used in $path, no need to preload"
        version=0
    else
        echo -e "$box:\tversion $version used in $path needs to be preloaded"
    fi
}

check_latest_version() {
    latest_version=$(curl -s "$box_info$1" | jq '.boxes[0].current_version.version|tonumber')

    current_version=$(vagrant box list | awk '/'$box' /{sub(/)/,"",$3);if($3>v){v=$3}} END{if(v)print v;else print "0"}')

    if ((current_version >= latest_version)) ; then
        echo -e "$box:\tlocal version $current_version >= remote version $latest_version, no need to preload"
        version=0
    else
        echo -e "$box:\tlocal version $current_version, remote version $latest_version needs to be preloaded"
        version=$latest_version
    fi
}

mkdir -p "$outdir"

for box in $boxes; do
    if [[ latest -eq 1 ]] ; then
        check_latest_version "$box"
    else
        check_defaults_version "$box"
    fi
    if [[ version -eq 0 ]] ; then
        continue
    fi

    set +e
    curl --fail "$vagrant_url$box/$version/lock" 2>/dev/null
    lock_exit_code=$?
    # check for 404 error indicating that cache is up and lock file is not in place
    if [ $lock_exit_code -eq 22 ]; then
        download_from_cache=true
    else
        # cache is down or box is locked
        download_from_cache=false
    fi

    ret=1

    if [[ $download_from_cache == true ]]; then
        echo "adding box from cache"
        curl --fail "$vagrant_url$box/$version/metadata.json" -o "$outdir/metadata.json"
        ret=$?
        if [[ $ret -eq 0 ]]; then
            url="$vagrant_url$box/$version/package.box"
            if [[ $use_aria2 -eq 1 ]] ; then
                $aria2c -d "$outdir" -o package.box "$url"
            else
                curl "$url" -o "$outdir/package.box"
            fi
            ret=$?
        fi
        if [[ $ret -eq 0 ]]; then
            pushd "$outdir"
            vagrant box add metadata.json
            ret=$?
            popd
        fi
    fi

    set -e
    if [[ $ret -ne 0 ]]; then
        echo "box locked or unavailable, adding box from vagrant cloud"
        if [[ $use_aria2 -eq 1 ]] ; then
            url="https://vagrantcloud.com/cilium/boxes/$box/versions/$version/providers/virtualbox.box"
            $aria2c -d "$outdir" -o package.box "$url"
            vagrant box add "cilium/$box" "$outdir/package.box"
            mkdir -p "$box_dir$box"
            if [[ ! -f $box_dir$box/metadata_url ]] ; then
                echo -n "https://vagrantcloud.com/cilium/$box" > "$box_dir$box/metadata_url"
            fi
            mv "$box_dir$box/0" "$box_dir$box/$version"
        else
            vagrant box add "cilium/$box" --box-version "$version"
        fi
    fi

    rm -f -- "$outdir/metadata.json"
    rm -f -- "$outdir/package.box"
done
