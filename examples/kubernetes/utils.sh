#!/usr/bin/env bash

function getIPv6 {
if [ -n "${dockerID}" ]; then
    pid=$(docker inspect ${dockerID} | grep '"Pid"' | grep -Eo [0-9]+)
    if [ -n "${pid}" ]; then
        sudo nsenter --net=/proc/${pid}/ns/net -F -- ip -o -6 addr show dev eth0 scope global | sed -e 's%.*inet6 \(.*\)\/.*%\1%'
    fi
fi
}
