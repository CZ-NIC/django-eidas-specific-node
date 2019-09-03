#!/bin/sh

echo -e "\nBuilding specific_proxy_service docker image\n==============================" \
    && docker build -f docker/Dockerfile.specific_proxy_service -t specific_proxy_service:latest .
