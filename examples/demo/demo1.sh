#!/bin/bash

set -x

sudo docker run --rm -ti --net cilium -l io.cilium.client noironetworks/nettools bash
