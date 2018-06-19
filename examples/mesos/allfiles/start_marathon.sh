#!/bin/bash

if [[ -z "$HOST_IP" ]]; then
    HOST_IP=192.168.44.11
fi

echo "Starting marathon..."
/home/vagrant/marathon/bin/marathon --master $HOST_IP:5050 &> ~/marathon.log &
until curl -o /dev/null -s 127.0.0.1:8080/v2/apps; do echo "..."; sleep 3s; done
echo "Done"
