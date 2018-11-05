FROM docker.io/library/python:3.6.7-alpine3.8

LABEL maintainer="maintainer@cilium.io"

ENV DOCS_DIR=/srv/Documentation
ENV API_DIR=/srv/api

ADD ./requirements.txt $DOCS_DIR/requirements.txt

ENV PACKAGES="\
    bash \
    ca-certificates \
    make \
    git \
    py-pip \
    sphinx-python \
    enchant \
    aspell-en \
"
RUN apk add --no-cache --virtual --update $PACKAGES && \
    pip install --upgrade pip
ARG GID
ARG UID
RUN addgroup -g $GID -S appuser 2>/dev/null || true && adduser -g $GID -D -u $UID appuser || true 2>/dev/null
RUN chmod 644 $DOCS_DIR/requirements.txt
USER appuser
RUN echo "PATH=\$PATH:/home/appuser/.local/bin" >> /home/appuser/.bashrc
RUN pip install --no-warn-script-location --user -r $DOCS_DIR/requirements.txt

WORKDIR $DOCS_DIR
ADD _api $API_DIR
ADD . $DOCS_DIR
