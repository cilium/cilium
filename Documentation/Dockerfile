FROM docker.io/library/python:3.7.9-alpine3.11

LABEL maintainer="maintainer@cilium.io"

RUN apk add --no-cache --virtual --update \
    aspell-en \
    nodejs \
    npm \
    bash \
    ca-certificates \
    enchant \
    git \
    libc6-compat \
    py-pip \
    python \
    sphinx-python \
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
RUN install -m 0777 -d /usr/local/lib/python3.7/site-packages/versionwarning/_static/data
