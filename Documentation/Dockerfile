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

## Workaround odd behaviour of sphinx versionwarning extension. It wants to
## write runtime data inside a system directory.
## We do rely on this extension, so we cannot just drop it.
RUN install -m 0777 -d /usr/local/lib/python3.10/site-packages/versionwarning/_static/data
