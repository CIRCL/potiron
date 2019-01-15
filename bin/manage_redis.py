#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bin.run_redis import shutdown_redis
from glob import glob
from lib.helpers import check_running, get_homedir, REDIS_BACKENDS
from redis import Redis
import argparse
import json
import os
import sys

_correct_answers = ('y', 'yes', 'n', 'no')
_to_call = {'4': '_create_redis', '2': '_delete_redis', '1': '_flush_redis'}
_to_read_files = ('redis.conf', 'run_redis.sh', 'shutdown_redis.sh')
_to_write_files = ('{name}.conf', 'run_redis.sh', 'shutdown_redis.sh')
_permissions = (0o644, 0o755, 0o755)


def _create_file(potiron_path, to_read, to_write, name, permission):
    with open("{}/lib/{}".format(potiron_path, to_read), 'rt', encoding='utf-8') as f:
        to_modify = f.read()
    current_path = "{}/redis_backends/{}".format(potiron_path, name)
    if not os.path.exists(current_path):
        os.makedirs(current_path)
    to_write_name = "{}/{}".format(current_path, to_write.format(name=name))
    with open(to_write_name, 'wt', encoding='utf-8') as f:
        f.write(to_modify.format(name=name))
    os.chmod(to_write_name, permission)


def _create_redis(names):
    if names is None:
        sys.exit('Please specify a name for the redis instance(s) you want to create.')
    potiron_path = get_homedir()
    for name in names:
        if name in REDIS_BACKENDS:
            print("{}: This redis backend already exists.".format(name))
            continue
        for to_read, to_write, permission in zip(_to_read_files, _to_write_files, _permissions):
            _create_file(potiron_path, to_read, to_write, name, permission)
        _update_redis_backends(name, 'creation')
        print("Successfully created {}".format(name))

def _deal_with_user_input(action, state):
    i = None
    while i not in _correct_answers:
        i = input("You are going to {} all the {} redis instances. Confirm? (y/n)".format(action, state))
        if i not in _correct_answers:
            print("Wrong input, please confirm if you want to {} all the {} redis instances (Y) or cancel and retype your command (N).".format(action, state))
    return None if i in ('y', 'yes') else sys.exit(0)


def _delete_redis(names):
    if names is None:
        _deal_with_user_input('delete', 'existing')
        names = REDIS_BACKENDS
    for name in names:
        if name not in REDIS_BACKENDS:
            print("{}: This redis backend does not exist.".format(name))
            continue
        if check_running(name):
            shutdown_redis(name)
        redis_path = "{}/redis_backends/{}".format(get_homedir(), name)
        try:
            for filename in glob("{}/*".format(redis_path)):
                os.remove(filename)
            os.rmdir(redis_path)
            _update_redis_backends(name, 'deletion')
            print('Successfully deleted {}.'.format(name))
        except Exception:
            print('Can not delete {}, please check if the directory actually exists.'.format(name))


def _flush_redis(names):
    if names is None:
        _deal_with_user_input('flush', 'running')
        names = REDIS_BACKENDS
    for name in names:
        if check_running(name):
            try:
                r = Redis(unix_socket_path=get_socket_path(name))
                r.flushdb()
                print('Successfully flushed {}.'.format(name))
            except Exception:
                print('Not able to flush {}. Please check if the instance is shutdown, or if it at least exists.'.format(name))
                continue


def _update_config_creation(config, name):
    redis_backends = config['redis_backends']
    redis_backends.append(name)
    return redis_backends


def _update_config_deletion(config, name):
    return [backend for backend in config['redis_backends'] if backend != name]


def _update_redis_backends(name, action):
    redis_backend_config = "{}/lib/redis_backends.json".format(get_homedir())
    with open(redis_backend_config, 'rt', encoding='utf-8') as f:
        config = json.loads(f.read())
    redis_backends = globals()['_update_config_{}'.format(action)](config, name)
    REDIS_BACKENDS = redis_backends
    config['redis_backends'] = redis_backends
    with open(redis_backend_config, 'wt', encoding='utf-8') as f:
        f.write(json.dumps(config, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage redis DBs creation / deletion / flush.')
    parser.add_argument('-c', '--create', action='store_true', default=False, help='Create the redis instance(s).')
    parser.add_argument('-d', '--delete', action='store_true', default=False, help='Delete the redis instance(s).')
    parser.add_argument('-f', '--flush', action='store_true', default=False, help='Flush the redis instance(s).')
    parser.add_argument('-n', '--name', nargs='+', type=str, help='Name of the redis instance(s) to interact with.')
    args = parser.parse_args()
    values = (4,2,1)
    n_args = sum(value for arg, value in zip((args.create, args.delete, args.flush), values) if arg)
    if n_args not in values:
        sys.exit('Please specify if you want to create, delete, or flush some redis instance(s). Only one choice at the same time.')
    globals()[_to_call[str(n_args)]](args.name)
