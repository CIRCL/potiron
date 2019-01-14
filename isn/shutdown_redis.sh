#!/bin/bash

set -x

../../redis/src/redis-cli -s ./isn.sock shutdown
