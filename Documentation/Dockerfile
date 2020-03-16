FROM docker.io/library/python:3.7.5-alpine3.10

LABEL maintainer="maintainer@cilium.io"

RUN apk add --no-cache --virtual --update \
    aspell-en \
    bash \
    ca-certificates \
    enchant \
    git \
    py-pip \
    python \
    sphinx-python \
    && true

ADD ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

## Workaround odd behaviour of sphinx versionwarning extension. It wants to
## write runtime data inside a system directory.
## We do rely on this extension, so we cannot just drop it.
RUN install -m 0777 -d /usr/local/lib/python3.7/site-packages/versionwarning/_static/data
