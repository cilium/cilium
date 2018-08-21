FROM alpine:3.7

LABEL "author"="Cilium"

ENV DOCS_DIR=/srv/Documentation
ENV API_DIR=/srv/api

ADD Documentation/requirements.txt $DOCS_DIR/requirements.txt

ENV PACKAGES="\
    bash \
    ca-certificates \
    make \
    git \
    python \
    py-pip \
    sphinx-python \
    enchant \
    aspell-en \
"
RUN apk add --no-cache --virtual --update $PACKAGES && \
    pip install --upgrade pip && \
    pip install -r $DOCS_DIR/requirements.txt

WORKDIR $DOCS_DIR
ADD api $API_DIR
ADD Documentation $DOCS_DIR
