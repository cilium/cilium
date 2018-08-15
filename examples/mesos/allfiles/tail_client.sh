#!/bin/bash
if [ "$1" == "goodclient" ] || [ "$1" == "badclient" ] 
  then
    tail -f `find /var/lib/mesos -name stdout | grep $1`
  else 
    echo "Invalid input. Please enter goodclient or badclient."
fi
