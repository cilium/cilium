#!/bin/bash

V4=$(ip -4 a show scope global | \
	grep -oEm 1 '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' | \
	head -1)

HEX=$(printf '%02X' ${V4//./ })

V6="beef::${HEX:0:4}:${HEX:4}:0"
echo "Running ./cilium-net-daemon -n $V6"

./cilium-net-daemon -n $V6
