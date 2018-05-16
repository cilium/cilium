FROM python:alpine
EXPOSE 8080
RUN /bin/sh
RUN pip install elasticsearch
COPY create.py .
COPY update.py .
COPY get_search.py .
CMD sleep 10000000
