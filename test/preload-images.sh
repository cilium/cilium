#!/usr/bin/env bash
set -e
for image in $(cat image-catalog.txt); do
	attempt=0
	max_attempts=6
	# Retry for about 2 minutes, with exponential backoff to
	# prevent overloading registry server rate limits.
	while [[ $attempt < ${max_attempts} ]] do
		echo "Attempting to pull $image (attempt $attempt)"
		docker pull $image && break
		attempt=$((attempt+1))
		timeout=$((2**$attempt))
		echo "Failed to pull $image, retrying in $timeout seconds (attempt $attempt/$max_attempts)"
		sleep ${timeout}
	done
	kind load docker-image $image
done
