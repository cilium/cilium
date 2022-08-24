FROM docker.io/library/python:3.10.4-alpine3.15

LABEL maintainer="maintainer@cilium.io"

RUN apk add --no-cache --virtual --update \
    aspell-en \
    nodejs \
    npm \
    bash \
    ca-certificates \
    enchant2 \
    enchant2-dev \
    git \
    libc6-compat \
    py-pip \
    python3 \
    py3-sphinx \
    gcc \
    musl-dev \
    && true

ADD ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

ENV HOME=/tmp
ENV READTHEDOCS_VERSION=$READTHEDOCS_VERSION
ENV MAKE_GIT_REPO_SAFE=1

## Workaround odd behaviour of sphinx versionwarning extension. It wants to
## write runtime data inside a system directory.
## We do rely on this extension, so we cannot just drop it.
RUN install -m 0777 -d /usr/local/lib/python3.10/site-packages/versionwarning/_static/data

## Recent Git versions refuse to work by default if the repository owner is
## different from the user. This is the case on macOS, because we run the
## container with --user "uid:gid", and they differ from what Linux is used to
## (The gid from macOS seems to be 20, which corresponds to the "dialout" group
## in the container). We pass --user "uid:gid" to have the "install" command
## work in the workaround for versionwarning above.
## Tell Git that this repository is safe.
RUN  git config --global --add safe.directory /src
