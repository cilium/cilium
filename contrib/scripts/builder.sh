#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/../.."

CILIUM_BUILDER_IMAGE=$(cat images/cilium/Dockerfile | grep '^ARG CILIUM_BUILDER_IMAGE=' | cut -d '=' -f 2)

GO="$(which go 2> /dev/null || :)"

USERID=$(id -u)
GROUPID=$(id -g)
USER_OPTION=(--user "$USERID:$GROUPID")
USER_PATH="/home/ubuntu"

# Ensure that the GOCACHE and GOMODCACHE directories exist, create as the
# current user if not: Docker would create it as root if they don't exist, and
# it wouldn't be writable by the user inside the container.

MOUNT_GOCACHE_DIR=()
if [ -n "${BUILDER_GOCACHE_DIR:-}" ]; then
	MOUNT_GOCACHE_DIR=(-v "${BUILDER_GOCACHE_DIR}:${USER_PATH}/.cache/go-build")
	mkdir -p "$BUILDER_GOCACHE_DIR"
elif [ -n "${GO}" ]; then
	GOCACHE=$("$GO" env GOCACHE)
	MOUNT_GOCACHE_DIR=(-v "$GOCACHE:$USER_PATH/.cache/go-build")
	mkdir -p "$GOCACHE"
fi

MOUNT_GOMODCACHE_DIR=()
if [ -n "${BUILDER_GOMODCACHE_DIR:-}" ]; then
	MOUNT_GOMODCACHE_DIR=(-v "${BUILDER_GOMODCACHE_DIR}:/go/pkg/mod")
	mkdir -p "$BUILDER_GOMODCACHE_DIR"
elif [ -n "${GO}" ]; then
	GOMODCACHE=$("$GO" env GOMODCACHE)
	MOUNT_GOMODCACHE_DIR=(-v "$GOMODCACHE:/go/pkg/mod")
	mkdir -p "$GOMODCACHE"
fi

MOUNT_CCACHE_DIR=()
LOCAL_CCACHE_DIR=$(ccache -k cache_dir 2> /dev/null || :)
if [ -n "${BUILDER_CCACHE_DIR:-}" ]; then
	MOUNT_CCACHE_DIR=(-v "$BUILDER_CCACHE_DIR:$USER_PATH/.cache/ccache")
	mkdir -p "$BUILDER_CCACHE_DIR"
elif [ -d "$LOCAL_CCACHE_DIR" ]; then
	MOUNT_CCACHE_DIR=(-v "$LOCAL_CCACHE_DIR:$USER_PATH/.cache/ccache")
fi

echo "Docker params: ${MOUNT_GOCACHE_DIR[@]} ${MOUNT_GOMODCACHE_DIR[@]} ${MOUNT_CCACHE_DIR[@]}"
CONTAINER=$(docker create \
	"${MOUNT_GOCACHE_DIR[@]}" \
	"${MOUNT_GOMODCACHE_DIR[@]}" \
	"${MOUNT_CCACHE_DIR[@]}" \
	-v "$PWD":/go/src/github.com/cilium/cilium \
	-w /go/src/github.com/cilium/cilium \
	"$CILIUM_BUILDER_IMAGE" \
	sleep infinity
)
trap 'docker rm -f "$CONTAINER"' EXIT
docker start "$CONTAINER"

EXISTING_GROUP=$(docker exec "$CONTAINER" getent group "$GROUPID" || :)
if [ -n "$EXISTING_GROUP" ] && [ "${EXISTING_GROUP%%:*}" != "ubuntu" ]; then
	echo "Group exists in the container, trying to reassign ID: $EXISTING_GROUP"
	NEW_GID=
	for gid in $(seq 1 999); do
		# groupmod fails if $gid is already in use.
		docker exec "$CONTAINER" groupmod -g "$gid" "${EXISTING_GROUP%%:*}" || continue
		docker exec "$CONTAINER" find / -xdev \
			-path /go -prune -o \
			-path /home -prune -o \
			-exec chown -hc --from=":$GROUPID" ":${EXISTING_GROUP%%:*}" {} +
		NEW_GID="$gid"
		break
	done
	if [ -n "$NEW_GID" ]; then
		echo "Reassigned group ${EXISTING_GROUP%%:*} to ID $NEW_GID"
	else
		echo "Failed to find an unused GID for group ${EXISTING_GROUP%%:*}"
		exit 1
	fi
fi
EXISTING_USER=$(docker exec "$CONTAINER" getent passwd "$USERID" || :)
if [ -n "$EXISTING_USER" ] && [ "${EXISTING_USER%%:*}" != "ubuntu" ]; then
	echo "User exists in the container, trying to reassign ID: $EXISTING_USER"
	NEW_UID=
	for uid in $(seq 1 999); do
		# usermod fails if $uid is already in use.
		docker exec "$CONTAINER" usermod -u "$gid" "${EXISTING_USER%%:*}" || continue
		# usermod only chowns inside the home directory. System users can own files elsewhere.
		docker exec "$CONTAINER" find / -xdev \
			-path /go -prune -o \
			-path /home -prune -o \
			-exec chown -hc --from="$USERID" "${EXISTING_USER%%:*}" {} +
		NEW_UID="$uid"
		break
	done
	if [ -n "$NEW_UID" ]; then
		echo "Reassigned user ${EXISTING_USER%%:*} to ID $NEW_UID"
	else
		echo "Failed to find an unused UID for user ${EXISTING_USER%%:*}"
		exit 1
	fi
fi

docker exec "$CONTAINER" groupmod -g "$GROUPID" ubuntu
# usermod fixes UIDs, but GIDs need to be fixed manually.
docker exec "$CONTAINER" chown -Rhc --from=:1000 :ubuntu /home/ubuntu
docker exec "$CONTAINER" usermod -u "$USERID" ubuntu
docker exec "$CONTAINER" chown -hc ubuntu:ubuntu /home/ubuntu/.cache
docker exec "${USER_OPTION[@]}" ${DOCKER_ARGS:+$DOCKER_ARGS} "$CONTAINER" "$@"
