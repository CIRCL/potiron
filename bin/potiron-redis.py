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
import pprint
import os

#List of fields that are included in the json documents that should not
#be ranked
#FIXME Put this as argument to the program as this list depends on the
#documents that is introduced
non_index = ['', 'filename','sensorname', 'timestamp', 'packet_id']


parser = argparse.ArgumentParser(description='Import IPSumpdump json documents\
into redis.')
parser.add_argument('--filename',type=str,nargs=1, help='Filename of a \
json document that should be imported.')
parser.add_argument('--unix',type=str,nargs=1, help='Unix socket to connect to \
redis-server.')

args = parser.parse_args()
if args.unix == None:
    sys.stderr.write('A unix socket must be specified\n')
    sys.exit(1)

usocket = args.unix[0]

if args.filename == None:
    sys.stderr.write('A filename must be specified\n')
    sys.exit(1)

filename = args.filename[0]

red = redis.Redis(unix_socket_path=usocket)

#Check if file was already imported
fn =  os.path.basename(filename)
if red.sismember("FILES", fn):
    sys.stderr.write('[INFO] Filename ' +fn+' was already imported ... skip ...\n')
    sys.exit(0)
red.sadd("FILES", fn)

f = open(filename,'r')
doc = json.load(f)
f.close()


#Get sensorname assume one document per sensor name

item = doc[0]
#FIXME documents must include at least a sensorname and a timestamp
#FIXME check timestamp format
sensorname = item['sensorname']
timestamp = item['timestamp']
(day, time) = timestamp.split(' ')
day = day.replace('-','')
red.sadd("DAYS",day)
for di in doc:
    p = red.pipeline()
    for k in di.keys():
        if not k in non_index:
            keyname = sensorname + ":" + day + ":" + k
            feature = di[k]
            p.sadd("FIELDS",k)
            p.zincrby(keyname, feature,1)
    #FIXME the pipe might be to big peridocially flush them
    p.execute()
