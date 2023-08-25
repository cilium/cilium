#!/usr/bin/env bash

K8S_NODES="${K8S_NODES:-2}"

vagrant destroy -f

i=1
while [ "$i" -le "$K8S_NODES" ]; do
    VBoxManage natnetwork remove --netname natnet$i
    i=$((i+1))
done

VBoxManage natnetwork list
