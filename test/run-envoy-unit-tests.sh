#!/bin/bash

set -e

vagrant ssh runtime -c "cd /home/vagrant/go/src/github.com/cilium/cilium ; make tests-envoy"
