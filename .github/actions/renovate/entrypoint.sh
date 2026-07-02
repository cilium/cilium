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

# In ghcr.io/renovatebot/renovate, the ubuntu user has GID 0 in /etc/passwd
# (ubuntu:x:12021:0::/home/ubuntu:/bin/bash). runuser -u ubuntu alone would
# therefore inherit GID 0, triggering the root-permissions workaround in
# builder.sh (which checks USERID -eq 0 || GROUPID -eq 0).
# -g ubuntu overrides the primary GID at the call site.
# -G "$GROUP_NAME" re-adds the docker socket group, which runuser drops
# because it starts a new login session (usermod -aG above is not inherited).
runuser -u ubuntu -g ubuntu -G "$GROUP_NAME" renovate
