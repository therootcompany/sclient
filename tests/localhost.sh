#!/bin/bash

go run -race ./cmd/sclient telebit.cloud:443 localhost:3000 &
my_pid=$!
sleep 5

nc localhost 3000 < tests/get.bin
kill $my_pid 2>/dev/null
