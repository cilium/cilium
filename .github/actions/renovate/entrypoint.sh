#!/bin/bash

apt update

apt install -y gettext docker-buildx

# Check if PS1 is unset; using ${PS1:-} to avoid "unbound variable" error
# in non-interactive shells.
sed -i '7s/\[ -z "$PS1" \]/[ -z "${PS1:-}" ]/' /etc/bash.bashrc

ls -lah /var/run/docker.sock

# Add the group of /var/run/docker.sock to ubuntu user
GROUP_ID=$(stat -c '%g' /var/run/docker.sock)
GROUP_NAME=$(getent group "$GROUP_ID" | cut -d: -f1)

if [ -z "$GROUP_NAME" ]; then
  GROUP_NAME="docker_group"
  groupadd -g "$GROUP_ID" "$GROUP_NAME"
fi

usermod -aG "$GROUP_NAME" ubuntu

runuser -u ubuntu renovate
