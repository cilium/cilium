#
# Cilium init container.
#
# cilium-init is used in kubernetes environments to run miscellaneous
# logic for setting up containers in between pod restarts.
#
FROM docker.io/cilium/cilium:latest
LABEL maintainer="maintainer@cilium.io"
COPY init-container.sh /init-container.sh
CMD ["/init-container.sh"]
