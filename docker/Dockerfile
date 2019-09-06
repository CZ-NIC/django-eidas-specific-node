# Development Dockerfile for eidas_node Django app.
# DO NOT USE IN PRODUCTION!
FROM ubuntu:18.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       git \
       libxml2-dev \
       libxmlsec1-dev \
       libxmlsec1-openssl \
       python3-dev \
       python3-pip \
       ssh-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/app/eidas_node/

WORKDIR /opt/app

RUN pip3 install pip setuptools -U
RUN pip3 install -e eidas_node[ignite]

EXPOSE 8000

ENV PYTHONPATH="/opt/app/:/opt/app/eidas_node/"
ENV DJANGO_SETTINGS_MODULE="eidas_node_cfg"
CMD ["django-admin", "runserver", "0.0.0.0:8000"]
