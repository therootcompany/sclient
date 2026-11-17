#!/bin/bash

cat tests/get.bin | go run -race ./cmd/sclient telebit.cloud:443
