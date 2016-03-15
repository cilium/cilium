#!/bin/bash

ADDR=$1
DEV=$2

set -e

HOST_IP=$(echo $ADDR | sed 's/:0$/:ffff/')

ip route add $HOST_IP/128 dev $DEV
ip route add $ADDR/112 via $HOST_IP
