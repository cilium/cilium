#!/usr/bin/env bash

worker=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep guestbook | cut -d' ' -f2)

NODE_PUBLIC_IP="192.168.34.11"

curl http://${NODE_PUBLIC_IP}:3000
