#!/usr/bin/env bash

worker=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep guestbook | cut -d' ' -f2)

NODE_PUBLIC_IP=$(gcloud compute instances describe ${worker} \
  --format 'value(networkInterfaces[0].accessConfigs[0].natIP)')

echo "Testing http://${NODE_PUBLIC_IP}:3000"

curl http://${NODE_PUBLIC_IP}:3000
