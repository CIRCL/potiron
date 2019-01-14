#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from lib.helpers import check_running, get_homedir, redis_backends
from pathlib import Path
from subprocess import Popen
import argparse
import time


def __get_status(backends):
    backend_status = {}
    for b in backends:
        try:
            oui = check_running(b)
            backend_status[b] = oui
        except Exception:
            backend_status[b] = False
    return backend_status


def launch_redis(redis_name, storage_directory: Path=None):
    if not storage_directory:
        storage_directory = get_homedir()
    if not check_running(redis_name):
        Popen(["./run_redis.sh"], cwd=(storage_directory / redis_name))


def shutdown_redis(redis_name, storage_directory: Path=None):
    if not storage_directory:
        storage_directory = get_homedir()
    Popen(["./shutdown_redis.sh"], cwd=(storage_directory / redis_name))


def check_all(backends, start, stop):
    backend_status = __get_status(backends)
    if not start and not stop:
        if all(status for status in backend_status.values()):
            return "All redis instances runnnig"
        if not any(status for status in backend_status.values()):
            return "All redis instances stopped"
        return "\n".join(["%s: %s" % (name, "running" if value else "down") for name, value in backend_status.items()])
    while True:
        for b in backend_status:
            try:
                backend_status[b] = check_running(b)
            except Exception:
                backend_status[b] = False
        if stop:
            if not any(status for status in backend_status.values()):
                return "All redis instances stopped"
        else:
            if all(status for status in backend_status.values()):
                return "All redis instances runnnig"
        for b, status in backend_status.items():
            if not stop and not status:
                print(f"Waiting on {b}")
            if stop and status:
                print(f"Waiting on {b}")
        time.sleep(1)


def launch_all(backends):
    for b in backends:
        launch_redis(b)


def shutdown_all(backends):
    for b in backends:
        shutdown_redis(b)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage redis DBs.')
    parser.add_argument('--start', action='store_true', default=False, help="Start all")
    parser.add_argument('--stop', action='store_true', default=False, help="Stop all")
    parser.add_argument("--status", action='store_true', default=True, help="Show status")
    parser.add_argument("-n", "--name", type=str, nargs='+', help="Name of the redis instance(s) to interact with. If no name is set, all the currently available instances will be considered.")
    args = parser.parse_args()
    backends = args.name if args.name is not None else redis_backends
    if args.start and args.stop:
        sys.exit("Please specify if you want either to start or stop redis, but not both.")
    if args.start:
        launch_all(backends)
    elif args.stop:
        shutdown_all(backends)
    if args.status:
        print(check_all(backends, args.start, args.stop))
