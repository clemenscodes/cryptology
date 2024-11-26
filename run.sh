#!/usr/bin/env bash

CONTAINER="cryptology"
CLI_NAME="$CONTAINER"

if [ -z "$1" ]; then
  CLI_ARGS="decrypt many-time-pad -i ciphertext.txt -o solution.txt"
else
  CLI_ARGS="$@"
fi

docker run -i --rm -v "$(pwd)":/app/ $CONTAINER $CLI_NAME $CLI_ARGS
