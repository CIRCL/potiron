#!/usr/bin/python
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2014 Gerard Wagener
#    Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import redis
import sys
import os
import potiron

# List of fields that are included in the json documents that should not
# be ranked
# FIXME Put this as argument to the program as this list depends on the
# documents that is introduced
non_index = ['', 'filename', 'sensorname', 'timestamp', 'packet_id']


parser = argparse.ArgumentParser(description='Import IPSumpdump json documents\
into redis.')
parser.add_argument('--filename', type=str, nargs=1, help='Filename of a \
json document that should be imported.')
parser.add_argument('--unix', type=str, nargs=1, help='Unix socket to connect to \
redis-server.')

args = parser.parse_args()
if args.unix is None:
    sys.stderr.write('A unix socket must be specified\n')
    sys.exit(1)

usocket = args.unix[0]

if args.filename is None:
    sys.stderr.write('A filename must be specified\n')
    sys.exit(1)

filename = args.filename[0]

red = redis.Redis(unix_socket_path=usocket)

# Check if file was already imported
fn = os.path.basename(filename)
if red.sismember("FILES", fn):
    sys.stderr.write('[INFO] Filename ' +fn+' was already imported ... skip ...\n')
    sys.exit(0)
red.sadd("FILES", fn)

f = open(filename, 'r')
doc = json.load(f)
f.close()

#Record local dictionaries
local_dicts = dict()
rev_dics = dict()

# Get sensorname assume one document per sensor name

item = doc[0]
# FIXME documents must include at least a sensorname and a timestamp
# FIXME check timestamp format
sensorname = potiron.get_sensor_name(doc)
lastday = None
revcreated = False

for di in doc:
    if di["type"] > potiron.DICT_BOUNDARY:
        local_dicts[di["type"]] = di
    if di["type"] == potiron.TYPE_PACKET:
        if revcreated == False:
            rev_dics = potiron.create_reverse_local_dicts(local_dicts)
            revcreated = True
        timestamp = di['timestamp']
        (day, time) = timestamp.split(' ')
        day = day.replace('-', '')
        if day != lastday:
            red.sadd("DAYS", day)
        p = red.pipeline()
        for k in di.keys():
            if k not in non_index:
                feature = potiron.translate_dictionaries(rev_dics, red, k, di[k])
                keyname = sensorname + ":" + day + ":" + k
                p.sadd("FIELDS", k)
                p.zincrby(keyname, feature, 1)
        # FIXME the pipe might be to big peridocially flush them
        p.execute()
