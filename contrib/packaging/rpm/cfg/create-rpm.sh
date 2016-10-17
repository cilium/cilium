#!/usr/bin/env bash

envsubst \\\$VERSION < cilium.spec > cilium.spec
fedpkg --dist f24 local
