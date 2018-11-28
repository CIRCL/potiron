#!/bin/bash

set -e
set -x

## Set the default home directory for this repo. ##
cd ..
export POTIRON_HOME='./'

## Install redis ##
git clone https://github.com/antirez/redis.git
cd redis
git checkout 5.0
make
make test
cd ..
