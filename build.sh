#!/usr/bin/env bash

CONTAINER=cryptology

echo "Building container $CONTAINER"

docker build . -t $CONTAINER
