#!/bin/bash

if [ "$1" == "goodclient" ] || [ "$1" == "badclient" ] 
  then
    export IP=`cilium endpoint list | grep web-server | awk '{print $7}'`
    sed "s/__WEBSERVER_IP__/$IP/g; s/__CLIENTTYPE__/$1/g" ./client-template.json > $1.json
  else
    echo "Invalid client name. Please enter goodclient or badclient."
fi
