#!/bin/bash

set -x

../../../redis/src/redis-cli -s ./standard.sock shutdown
