#
# Cilium init container.
#
# cilium-init is used in kubernetes environments to run miscellaneous
# logic for cleaning up containers in between pod restarts.
#
FROM docker.io/library/busybox:1.28.4
LABEL maintainer="maintainer@cilium.io"
COPY init-container.sh /init-container.sh
CMD ["/init-container.sh"]
