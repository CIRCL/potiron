#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from lib.helpers import check_running, get_homedir, redis_backends
from pathlib import Path
from subprocess import Popen
import argparse
import time


def launch_redis(redis_name, storage_directory: Path=None):
    if not storage_directory:
        storage_directory = get_homedir()
    if not check_running(redis_name):
        Popen(["./run_redis.sh"], cwd=(storage_directory / redis_name))


def shutdown_redis(redis_name, storage_directory: Path=None):
    if not storage_directory:
        storage_directory = get_homedir()
    Popen(["./shutdown_redis.sh"], cwd=(storage_directory / redis_name))


def check_redis(stop=False):
    backends = {b: False for b in redis_backends}
    while True:
        for b in backends:
            try:
                backends[b] = check_running(b)
            except Exception:
                backends[b] = False
        if stop:
            if not any(status for status in backends.values()):
                print("All redis instances stopped")
                break
        else:
            if all(status for status in backends.values()):
                print("All redis instances runnnig")
                break
        for b, status in backends.items():
            if not stop and not status:
                print(f"Waiting on {b}")
            if stop and status:
                print(f"Waiting on {b}")
        time.sleep(1)


def launch_all():
    for b in redis_backends:
        launch_redis(b)


def shutdown_all():
    for b in redis_backends:
        shutdown_redis(b)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage redis DBs.')
    parser.add_argument('--start', action='store_true', default=False, help="Start all")
    parser.add_argument('--stop', action='store_true', default=False, help="Stop all")
    parser.add_argument("--status", action='store_true', default=True, help="Show status")
    args = parser.parse_args()
    stop = False
    if args.start:
        launch_all()
    elif args.stop:
        shutdown_all()
        stop = True
    if not args.stop and args.status:
        check_redis(stop)
