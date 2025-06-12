##############
# Base image #
##############
FROM ubuntu:22.04 AS base

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    libengine-pkcs11-openssl \
    libxml2-dev \
    libxmlsec1-openssl \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    ssh-client \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN adduser --home /app --disabled-password --gecos 'Eidas' eidas \
 && chmod go+rx /app

############################
# Build Python Environment #
############################
FROM base AS venv
RUN apt-get --yes update \
 && apt-get install --yes --no-install-recommends \
    # Build tools
    build-essential \
    # For xmlsec
    libxmlsec1-dev \
    # For xmlsec
    pkg-config \
    # For xmlsec
    zlib1g-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Create and use virtualenv
RUN python3 -m venv /app/venv
# Install pip and wheel first, so we can benefit from it
RUN python3 -m pip install --upgrade --no-cache-dir pip wheel \
 && python3 -m pip install --no-cache-dir pip-tools


############################
# Build Python Application #
############################
FROM venv AS build
COPY . /opt/app/eidas_node/

WORKDIR /opt/app/eidas_node
RUN pip3 install . --no-binary xmlsec --no-binary lxml

##########################
# Final Production Image #
##########################
FROM base AS final
COPY --from=build /app/venv /app/venv
RUN apt-get --yes update \
 && apt-get install --yes --no-install-recommends \
    # lxml
    libxml2 \
    opensc \
    softhsm2 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN . /app/venv/bin/activate

ENV PYTHONPATH="/app/uwsgi:$PYTHONPATH"
ENV DJANGO_SETTINGS_MODULE="eidas_node_cfg"

USER eidas:eidas

EXPOSE 8000

CMD ["django-admin", "runserver", "0.0.0.0:8000"]
