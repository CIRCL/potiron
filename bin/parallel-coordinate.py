#!/usr/bin/env python3

import redis
import argparse
import sys
import os
import calendar
from potiron_graph_annotation import field2string

def output_name(source, field, date, dest):
    return "{}parallel-coordinate_{}_{}_{}-{}".format(dest,source,field,date[0:4],date[4:6])

parser = argparse.ArgumentParser(description='Export one month data from redis')
parser.add_argument("-s","--source", type=str, nargs=1, help="Data source")
parser.add_argument("-d","--date", type=str, nargs=1, help='Date of the informations to display')
parser.add_argument("-f","--field", type=str, nargs=1, help="Field used")
parser.add_argument("-l","--limit", type=int, nargs=1, help="Limit of values to display")
parser.add_argument("-o","--outputdir", type=str, nargs=1, help="Output directory")
parser.add_argument("-u","--unix", type=str, nargs=1, help='Unix socket to connect to redis-server.')
args = parser.parse_args()

if args.source is None:
    source = "potiron"
else:
    source = args.source[0]

if args.date is None:
    sys.stderr.write('A date must be specified.\nThe format is : YYYYMM\n')
    sys.exit(1)
date = args.date[0]
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
if not os.path.exists(outputdir):
    os.makedirs(outputdir)

if args.unix is None:
    sys.stderr.write('A Unix socket must be specified.\n')
    sys.exit(1)
usocket = args.unix[0]
r = redis.Redis(unix_socket_path=usocket)

potiron_path = os.path.dirname(os.path.realpath(__file__))[:-3]

field_string, field_in_file_name = field2string(field, potiron_path)

days = calendar.monthrange(int(date[0:4]), int(date[4:6]))[1]
outputname = output_name(source,field_in_file_name,date,outputdir)
if not os.path.exists(outputname):
    os.makedirs(outputname)
f = open("{}.csv".format(outputname), 'w')
days_string = "ip,"
for day in range(1,days+1):
    d = format(day, '02d')
    days_string += "{}-{},".format(month,d)
f.write("{}\n".format(days_string[:-1]))
val = {}
for d in range(1,days+1):
    redisKey = "{}:{}{}:{}".format(source, date, format(d, '02d'), field)
    if r.exists(redisKey):
        for v in r.zrevrange(redisKey, 0, sys.maxsize)[:limit]:
            v = v.decode()
            if v not in val:
                val[v] = {}
            val[v][d] = r.zscore(redisKey, v)
for line in val:
    line_string="{},".format(line)
    for value in range(1,days+1):
        if value in val[line]:
            line_string += "{},".format(val[line][value])
        else:
            redisKey = "{}:{}{}:{}".format(source, date, format(value, '02d'), field)
            score = r.zscore(redisKey,val[line])
            if score is not None:
                line_string += "{},".format(score)
            else:
                line_string += "0,"
    f.write("{}\n".format(line_string[:-1]))
f.close()