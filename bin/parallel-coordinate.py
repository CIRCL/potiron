#!/usr/bin/env python3
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2017 Christian Studer
#    Copyright (C) 2017 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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

import redis
import argparse
import sys
import os
import calendar
from potiron_graph_annotation import field2string

MAXVAL = sys.maxsize

def output_name(source, field, date, dest):
    return "{}parallel-coordinate_{}_{}_{}-{}".format(dest,source,field,date[0:4],date[4:6])

parser = argparse.ArgumentParser(description='Export one month data from redis')
parser.add_argument("-s","--source", type=str, nargs=1, help='Sensor used as source (ex: "chp-5890-1")')
parser.add_argument("-d","--date", type=str, nargs=1, help='Date of the informations to display (with the format YYYY-MM)')
parser.add_argument("-f","--field", type=str, nargs=1, help='Field used (ex: "ipsrc")')
parser.add_argument("-l","--limit", type=int, nargs=1, help="Limit of values to display")
parser.add_argument("-o","--outputdir", type=str, nargs=1, help="Output directory")
parser.add_argument("-u","--unix", type=str, nargs=1, help='Unix socket to connect to redis-server.')
args = parser.parse_args()

if args.source is None:
    source = "potiron"
else:
    source = args.source[0]

if args.date is None:
    sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
    sys.exit(1)
date = args.date[0].replace("-","")
month = date[4:6]

if args.field is None:
    sys.stderr.write('A field must be specified.\n')
    sys.exit(1)
field = args.field[0]

if args.limit is None:
    limit = 20
else:
    limit = args.limit[0]

if args.outputdir is None:
    outputdir = "./out/"
else:
    outputdir = args.outputdir[0]
    if not outputdir.endswith('/'):
        outputdir = "{}/".format(outputdir)
if not os.path.exists(outputdir):
    os.makedirs(outputdir)

if args.unix is None:
    sys.stderr.write('A Unix socket must be specified.\n')
    sys.exit(1)
usocket = args.unix[0]
r = redis.Redis(unix_socket_path=usocket)

potiron_path = os.path.dirname(os.path.realpath(__file__))[:-3]

field_string, field_in_file_name = field2string(field, potiron_path)

ck = r.sismember("CK", "YES")
protocols = r.smembers("PROTOCOLS")

days = calendar.monthrange(int(date[0:4]), int(date[4:6]))[1]
outputname = output_name(source,field_in_file_name,date,outputdir)
if not os.path.exists(outputdir):
    os.makedirs(outputdir)
f = open("{}.csv".format(outputname), 'w')
days_string = "{},".format(field_in_file_name)
for day in range(1,days+1):
    d = format(day, '02d')
    days_string += "{}-{},".format(month,d)
f.write("{}\n".format(days_string[:-1]))
val = {}
if ck:
    for prot in protocols:
        protocol = prot.decode()
        keys = r.keys("{}:{}:{}*:{}".format(source,protocol,date,field))
        for k in sorted(keys):
            redisKey = k.decode()
            d = redisKey.split(":")[2][-2:]
            for v in r.zrevrangebyscore(redisKey,MAXVAL,0)[:limit]:
                countValue = r.zscore(redisKey, v)
                v = v.decode()
                if v not in val:
                    val[v] = {}
                s = r.zscore(redisKey, v)
                if d in val[v]:
                    val[v][d] += s
                else:
                    val[v][d] = s
else:
    keys = r.keys("{}:{}*:{}".format(source,date,field))
    for key in sorted(keys):
        k = key.decode()
        d = k.split(":")[1][-2:]
        for v in r.zrevrangebyscore(k, 0, sys.maxsize)[:limit]:
            v = v.decode()
            if v not in val:
                val[v] = {}
            val[v][d] = r.zscore(k, v)

for line in val:
    line_string="{},".format(line)
    for value in range(1,days+1):
        value = format(value, '02d')
        if value in val[line]:
            line_string += "{},".format(val[line][value])
        else:
            redisKey = "{}:{}{}:{}".format(source, date, value, field)
            score = r.zscore(redisKey,val[line])
            if score is not None:
                line_string += "{},".format(score)
            else:
                line_string += "0,"
    f.write("{}\n".format(line_string[:-1]))
f.close()
