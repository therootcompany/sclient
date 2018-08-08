#!/bin/bash

go run -race sclient*.go telebit.cloud:443 localhost:3000 &
my_pid=$!
sleep 5

netcat localhost 3000 < tests/get.bin
kill $my_pid
