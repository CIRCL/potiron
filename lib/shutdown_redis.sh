#!/bin/bash

set -x

../../../redis/src/redis-cli -s ./{name}.sock shutdown
