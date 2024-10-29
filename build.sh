#!/usr/bin/env bash

CONTAINER=cryptology

echo "Building docker image $CONTAINER"

docker build . -t $CONTAINER
