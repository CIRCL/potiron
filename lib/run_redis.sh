#!/bin/bash

set -e
set -x

../../../redis/src/redis-server ./{name}.conf
