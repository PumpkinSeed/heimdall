#!/usr/bin/env bash

docker run -d \
  --name consul \
  --hostname consul \
  --network vault_network \
  -e CONSUL_HTTP_TOKEN=89C2B840-CDE0-4E77-ACAF-73EABB7A489B \
  -p 8300:8300 -p 8500:8500 -p 8600:8600/udp \
  -v $PWD/consul.json:/config.json \
  consul:latest consul agent -bind=0.0.0.0 -config-file=/config.json