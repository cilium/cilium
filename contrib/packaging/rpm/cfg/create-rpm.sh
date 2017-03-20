#!/usr/bin/env bash

envsubst \\\$VERSION < cilium.spec.env > cilium.spec
fedpkg --dist f24 local
