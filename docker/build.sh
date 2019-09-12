#!/bin/sh

echo -e "\nBuilding eidas_node:latest docker image\n==============================" \
    && docker build -f docker/Dockerfile -t eidas_node:latest .
