#!/usr/bin/env python3

import redis
import argparse
import sys
import os
import calendar
from potiron_graph_annotation import field2string,bubble_annotation

# Definition of the output file name
def output_name(source, field, dest, yearmonth, day):
    return "{}{}_{}_{}-{}-{}".format(dest,source,field,yearmonth[0:4],yearmonth[4:6],day)

# Parameters parser
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
    source = "potiron"
else:
    source = args.source[0]

if args.date is None:
    sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
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

# Project directory
potiron_path = os.path.dirname(os.path.realpath(__file__))[:-3]

# Definition of the strings containing the informations of the field, used in the legend and the file name
field_string, field_in_file_name = field2string(field, potiron_path)

days = calendar.monthrange(int(date[0:4]),int(date[4:6]))[1]
# For each day of the month
for d in range(1,days+1):
    redisKey = "{}:{}{}:{}".format(source, date, format(d, '02d'), field)
    if r.exists(redisKey):
        l = 0
        values = []
        # For each value ranged in decreasing order
        for v in r.zrevrangebyscore(redisKey,sys.maxsize,0):
            val = v.decode()
            # If the current value is not one that should be skipped, increment the number of values to include in the chart
            if val not in args.skip :
                values.append(val)
                l += 1
            # When the limit value is reached, we don't need to increment anymore, we break the loop
            if l >= limit:
                break
        # Write all the values and their scores into the csv datafile
        with open("{}.csv".format(output_name(source,field_in_file_name,outputdir,date,format(d, '02d'))),'w') as f:
            f.write("id,value\n")
            for v in values:
                val = bubble_annotation(field,field_string,v,potiron_path)
                f.write("{}{},\n".format(v,val))
                f.write("{}{},{}\n".format(v,val,r.zscore(redisKey,v)))
