#!/usr/bin/env python3
import redis
import argparse
import sys
import os
from bokeh.plotting import figure, output_file, show, ColumnDataSource
from bokeh.models import HoverTool,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool

days = ["01","02","03","04","05","06","07","08","09","10",
        "11","12","13","14","15","16","17","18","19","20",
        "21","22","23","24","25","26","27","28","29","30","31"]
parser = argparse.ArgumentParser(description='Export redis values in a graph.')
parser.add_argument('--field', type=str, nargs=1, help='Field that should be displayed.')
parser.add_argument('--date', type=str, nargs=1, help='Date of the informations to display')
parser.add_argument('--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
parser.add_argument('--value', help='Specific value of the field to display')
parser.add_argument('--dest', type=str, help='Destination path for the output file')
args = parser.parse_args()

if args.unix is None:
    sys.stderr.write('A Unix socket must be specified.\n')
    sys.exit(1)
    
usocket = args.unix[0]
red = redis.Redis(unix_socket_path=usocket)

if args.field is None:
    sys.stderr.write('A field must be specified.\nChoose one of these : '+red.smembers('FIELDS')+'\n')
    sys.exit(1)
field = args.field[0]
    
if args.date is None:
    sys.stderr.write('A date must be specified.\nThe format is : AAAAMM')
    sys.exit(1)
date = args.date[0]

if args.value is None:
    sys.stderr.write('A value must be specified\n')
    sys.exit(1)
fieldvalue = args.value

if args.dest is None:
    destpath = "./"
else:
    if not os.path.exists(args.dest):
        os.makedirs(args.dest)
    destpath = args.dest

redisKeyMonth = "chp-5577-1:"+str(date)
dayValue=[]
score=[]
exists = False
for d in days:
    if red.exists(str(redisKeyMonth+d+":"+field)):
        redisKey = redisKeyMonth+d+":"+field
        countValue = red.zscore(redisKey, fieldvalue)
        score.append(countValue if countValue is not None else 0)
        dayValue.append(d)
        exists = True

if exists:
    output_file(str(destpath+redisKeyMonth+"_"+field+"_"+fieldvalue+".html"), title=redisKey)
    source = ColumnDataSource(data=dict(count=score,days=dayValue))
    TOOLS = [HoverTool(tooltips=[("count","@count")]),PanTool(),BoxZoomTool(),WheelZoomTool(), SaveTool(), ResetTool()]
    p = figure(width=1500,height=750,tools=TOOLS)
    p.circle('days','count',size=12,source=source)
    p.line(dayValue,score,legend=field)
    p.title.text = str("Numbers of " + field + " " + fieldvalue + " seen for each day on month " + date[4:6] + ", year " + date[0:4])
    show(p)
else:
    print ("There is no such value for the " + field + " you specified\n")
