#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import redis
import argparse
import sys
import os
from potiron_graph_annotation import field2string,bubble_annotation

def output_name(source, field, date, dest):
    return "{}{}_{}_{}-{}-{}".format(dest,source,field,date[0:4],date[4:6],date[6:8])

parser = argparse.ArgumentParser(description='Export one day data from redis')
parser.add_argument("-s","--source", type=str, nargs=1, help="Data source")
parser.add_argument("-d","--date", type=str, nargs=1, help='Date of the informations to display')
parser.add_argument("-f","--field", type=str, nargs=1, help="Field used")
parser.add_argument("-l","--limit", type=int, nargs=1, help="Limit of values to export - default 20")
parser.add_argument("--skip", type=str, default=None, action="append", help="Skip a specific value")
parser.add_argument("-o","--outputdir", type=str, nargs=1, help="Output directory")
parser.add_argument("-u","--unix", type=str, nargs=1, help='Unix socket to connect to redis-server.')
args = parser.parse_args()

if args.source is None:
    source = "potiron"
else:
    source = args.source[0]

if args.date is None:
    sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM-DD')
    sys.exit(1)
date = args.date[0].replace("-","")

if args.field is None:
    sys.stderr.write('A field must be specified.\n')
    sys.exit(1)
field = args.field[0]

if args.limit is None:
    limit = 20
else:
    limit = args.limit[0]

if args.skip is None:
    args.skip = ['']

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

redisKey = "{}:{}:{}".format(source, date, field)
if r.exists(redisKey):
    l = 0
    values = []
    for v in r.zrevrangebyscore(redisKey,sys.maxsize,0):
        val = v.decode()
        if val not in args.skip :
            values.append(val)
            l += 1
        if l >= limit:
            break
    with open("{}.csv".format(output_name(source,field_in_file_name,date,outputdir)),'w') as f:
        f.write("id,value\n")
        for v in values:
            val = bubble_annotation(field,field_string,v,potiron_path)
            f.write("{}{},\n".format(v,val))
            f.write("{}{},{}\n".format(v,val,r.zscore(redisKey,v)))
