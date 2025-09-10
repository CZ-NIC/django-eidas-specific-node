# Development Dockerfile for eidas_node Django app.
# DO NOT USE IN PRODUCTION!
FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       git \
       libengine-pkcs11-openssl \
       libxml2-dev \
       libxmlsec1-dev \
       libxmlsec1-openssl \
       pkg-config \
       python3-dev \
       python3-pip \
       softhsm2 \
       opensc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/app/eidas_node/

WORKDIR /opt/app

RUN pip3 install pip -U
RUN pip3 install --upgrade --force-reinstall 'xmlsec<=1.3.15' 'lxml~=5.0' --no-binary="":all:""
RUN pip3 install tox tox-ipdb-plugin
RUN pip3 install -e eidas_node[ignite]

EXPOSE 8000

ENV PYTHONPATH="/opt/app/:/opt/app/eidas_node/"
ENV DJANGO_SETTINGS_MODULE="eidas_node_cfg"
CMD ["django-admin", "runserver", "0.0.0.0:8000"]
