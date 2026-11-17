#!/bin/bash

go run -race ./cmd/sclient telebit.cloud:443 - < ./tests/get.bin
