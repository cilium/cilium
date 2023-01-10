#!/usr/bin/env bash

apt-get -y install python3-software-properties software-properties-common
apt-add-repository -y ppa:zanchey/asciinema
apt-get -y update
apt-get -y install asciinema python3-setuptools
