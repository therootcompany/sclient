#!/bin/bash

cat tests/get.bin | go run -race sclient*.go telebit.cloud:443
