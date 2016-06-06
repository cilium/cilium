#!/bin/bash

set -x

sudo docker run --rm -ti --net cilium -l io.cilium.public noironetworks/nettools bash
