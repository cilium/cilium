#!/usr/bin/env bash

cd /root
source envs
envsubst < cilium.spec.envsubst > cilium.spec
fedpkg --release f25 local
