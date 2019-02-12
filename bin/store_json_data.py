#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2019 Christian Studer
#    Copyright (C) 2019 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from bin.parse_pcap_files import fetch_files
from pathlib import Path
from potiron.potiron_redis import process_storage
import argparse
import json
import os
import redis
import sys


def _pick_parameters(red, inputfile, ck):
    with open(inputfile, 'rt', encoding='utf-8') as f:
        packet = json.loads(f.read())[0]
    format = packet['format']
    if format == 'standard':
        red.rpush('JSON_FIELDS', *_JSON_FIELDS)
        red.hmset('PARAMETERS', {key: value for key, value in zip(('ck', 'format', 'tshark_filter'), (ck, format, packet['tshark_filter']))})
    else:
        red.hmset('PARAMETERS', {key: value for key, value in zip(('format', 'tshark_filter'), (format, packet['tshark_filter']))})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-i', '--input', type=str, nargs='+', required=True, help='JSON file to import')
    parser.add_argument("-c", "--console", action='store_false', help="DO NOT log output also to console")
    parser.add_argument('-u','--unix', type=str, nargs=1, required=True, help='Unix socket to connect to redis-server')
    parser.add_argument('-ck', '--combined_keys', action='store_true', help='Set if combined keys should be used')
    args = parser.parse_args()
    logconsole = args.console
    ck = args.combined_keys
    usocket = args.unix[0]
    try:
        red = redis.Redis(unix_socket_path=usocket, decode_responses=True)
    except redis.ConnectionError as e:
        sys.exit(f"Could not connect to redis. {e}")
    for arg in args.input:
        if os.path.exists(arg) is False:
            sys.stderr.write(f"The filename {arg} was not found\n")
            sys.exit(1)
    input_directory = [Path(arg) for arg in args.input]
    files = [filename for directory in input_directory for filename in fetch_files(directory, ('.json',))]
    if not red.keys("PARAMETERS"):
        _pick_parameters(red, files[0], ck)
    process_storage(red, files, ck, logconsole)
