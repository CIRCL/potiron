#!/usr/bin/env python3

import redis
import argparse
import sys
import os
import calendar

def output_name(source, field, dest, yearmonth, day):
    return "{}{}_{}_{}{}".format(dest,source,field,yearmonth,day)

parser = argparse.ArgumentParser(description='Export one month data from redis')
parser.add_argument("-s","--source", type=str, nargs=1, help="Data source")
parser.add_argument("-d","--date", type=str, nargs=1, help='Date of the informations to display')
parser.add_argument("-f","--field", type=str, nargs=1, help="Field used")
parser.add_argument("-l","--limit", type=int, nargs=1, help="Limit of values to export - default 20")
parser.add_argument("--skip", type=str, default=None, action="append", help="Skip a specific value")
parser.add_argument("-o","--outputdir", type=str, nargs=1, help="Output directory")
parser.add_argument("-u","--unix", type=str, nargs=1, help='Unix socket to connect to redis-server.')
args = parser.parse_args()

if args.source is None:
    args.source = ["potiron"]

if args.date is None:
    sys.stderr.write('A date must be specified.\nThe format is : YYYYMM')
    sys.exit(1)
date = args.date[0]

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
if not os.path.exists(outputdir):
    os.makedirs(outputdir)

if args.unix is None:
    sys.stderr.write('A Unix socket must be specified.\n')
    sys.exit(1)
usocket = args.unix[0]
r = redis.Redis(unix_socket_path=usocket)

days = calendar.monthrange(int(date[0:4]),int(date[4:6]))[1]
for d in range(1,days+1):
    currentLimit = limit
    redisKey = "{}:{}{}:{}".format(args.source[0], date, format(d, '02d'), args.field[0])
    if r.exists(redisKey):
        for v in r.zrevrangebyscore(redisKey,sys.maxsize,0)[:limit]:
            val = v.decode()
            if val in args.skip :
                currentLimit+=1
        with open("{}.csv".format(output_name(args.source[0],args.field[0],outputdir,date,format(d, '02d'))),'w') as f:
            f.write("id,value\n")
            for v in r.zrevrangebyscore(redisKey,sys.maxsize,0)[:currentLimit]:
                val = v.decode()
                if val in args.skip :
                    continue
                f.write("{},\n".format(val))
                f.write("{},{}\n".format(val,r.zscore(redisKey,val)))
