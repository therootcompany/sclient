#!/bin/bash

go run -race sclient*.go telebit.cloud:443 - < ./tests/get.bin
