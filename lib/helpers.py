#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import MissingEnv
from pathlib import Path
from redis import StrictRedis
from redis.exceptions import ConnectionError
import json
import os



def get_homedir():
    if not os.environ.get('POTIRON_HOME'):
        guessed_home = Path(__file__).resolve().parent.parent
        raise MissingEnv(f"POTIRON_HOME is missing. \
        Run the following command (assuming you run the code from the clonned repository):\
        export POTIRON_HOME='{guessed_home}/'")
    return Path(os.environ['POTIRON_HOME'])


def _get_redis_backends():
    with open("{}/lib/redis_backends.json".format(get_homedir()), 'rt', encoding='utf-8') as f:
        config = json.loads(f.read())
    return config['redis_backends']


REDIS_BACKENDS = _get_redis_backends()


def get_socket_path(name: str):
    mapping = {b: Path(b, "{}.sock".format(b)) for b in REDIS_BACKENDS}
    return str(get_homedir() / mapping[name])


def check_running(name: str):
    socket_path = get_socket_path(name)
    try:
        r = StrictRedis(unix_socket_path=socket_path)
        return r.ping()
    except ConnectionError:
        return False
