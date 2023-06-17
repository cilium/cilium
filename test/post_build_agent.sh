#!/usr/bin/env bash

echo "output of following commands are ran on the Jenkins agent itself"
echo "output of: \"ps -ef | grep -i vbox\" "
ps -ef | grep -i vbox

echo "output of: \"ps -ef | grep -i vagrant\" "
ps -ef | grep -i vagrant

echo "output of: \"VBoxManage --version\" "
VBoxManage --version

echo "output of: \"VBoxManage list runningvms\" "
VBoxManage list runningvms

echo "output of: \"VBoxManage list intnets\" "
VBoxManage list intnets
