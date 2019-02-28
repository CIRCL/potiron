#!/bin/bash

set -e
set -x

## Install redis ##
sudo apt-get install -y tcl8.5 libgeoip-dev tshark
git clone https://github.com/antirez/redis.git
cd redis
git checkout 5.0
make
make test
cd ..
