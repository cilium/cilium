FROM python:alpine
EXPOSE 8080
RUN /bin/sh
RUN pip install elasticsearch
COPY create.py .
CMD ['sleep', '10000000']
