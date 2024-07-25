# Python version should match the one in use in Read The Docs
FROM docker.io/library/python:3.11-alpine3.17 AS docs-base

LABEL maintainer="maintainer@cilium.io"

RUN apk add --no-cache --virtual --update \
    aspell-en \
    bash \
    ca-certificates \
    enchant2 \
    enchant2-dev \
    imagemagick \    
    git \
    py3-sphinx \
    gcc \
    && true

FROM docs-base AS docs-builder
ADD ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

ENV HOME=/tmp
ENV READTHEDOCS_VERSION=$READTHEDOCS_VERSION
ENV MAKE_GIT_REPO_SAFE=1

## Workaround odd behaviour of sphinx versionwarning extension. It wants to
## write runtime data inside a system directory.
## We do rely on this extension, so we cannot just drop it.
RUN install -m 0777 -d /usr/local/lib/python3.11/site-packages/versionwarning/_static/data
