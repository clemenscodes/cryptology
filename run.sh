#!/usr/bin/env bash

CONTAINER="cryptology"
CLI_NAME="$CONTAINER"
CLI_ARGS="$@"

docker run --rm -v "$(pwd)":/app/ $CONTAINER $CLI_NAME $CLI_ARGS
