FROM docker.io/library/ubuntu:20.04@sha256:f2034e7195f61334e6caff6ecf2e965f92d11e888309065da85ff50c617732b8 as builder

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    software-properties-common
RUN add-apt-repository universe
RUN apt-get update && apt-get install -y \
    apache2 \
    curl \
    git \
    libapache2-mod-php7.4 \
    php7.4 \
    php7.4-mysql \
    python3.4 \
    python3-pip
RUN pip3 install grpcio grpcio-tools
WORKDIR /tmp
RUN git clone -b v1.7.0 https://github.com/grpc/grpc
COPY cloudcity.proto /tmp/grpc/examples/protos
RUN mkdir -p /tmp/grpc/examples/python/cloudcity
COPY cc_door_client.py /tmp/grpc/examples/python/cloudcity
COPY cc_door_server.py /tmp/grpc/examples/python/cloudcity
WORKDIR /tmp/grpc/examples/python/cloudcity
RUN python3 -m grpc_tools.protoc \
    -I../../../examples/protos --python_out=. \
    --grpc_python_out=. \
    ../../../examples/protos/cloudcity.proto

FROM docker.io/library/ubuntu@sha256:e6173d4dc55e76b87c4af8db8821b1feae4146dd47341e4d431118c7dd060a74
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && pip3 install grpcio grpcio-tools \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY --from=builder /tmp/grpc/examples/python/cloudcity /cloudcity
