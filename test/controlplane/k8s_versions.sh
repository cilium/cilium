#!/usr/bin/env bash

versions=($(cat < "$(get_local_dir)/k8s_versions.txt" | grep -Eo '^[0-9]\.[0-9]{2}' | tr "\n" " "))
