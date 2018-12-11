FROM python:3.7

WORKDIR /aws
ADD . /aws
COPY version.h /usr/include/linux/version.h
COPY tls.h /usr/include/linux/tls.h
RUN git clone https://github.com/openssl/openssl.git ./openssl && 		  \
     cd ./openssl && git fetch origin pull/5253/head:ktls && git checkout ktls && \
     ./config enable-ktls --openssldir=/usr/local/ssl --prefix=/usr/local/ssl/&&  \
     make && make install && cd ..
RUN pip install awscli --user
ENV LD_LIBRARY_PATH=".:${LD_LIBRARY_PATH}"
ENV PATH="${PATH}:~/.local/bin/"
RUN mkdir ~/.aws
COPY config /root/.aws/config
COPY credentials /root/.aws/credentials
CMD ["/bin/bash"]
